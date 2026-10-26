// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Big.sol";

/// @title PrivacyLedger
/// @notice On-chain rules for secure federated learning with differential privacy.
///
/// Roles (separate accounts, every action is a signed transaction):
///   owner   - registers clients and sets the audit rate
///   server  - the (untrusted) aggregator: opens rounds, posts the aggregate
///   auditor - reports audit outcomes
///   clients - hospitals: declare noise, commit to updates, mark "submitted"
///
/// What the contract enforces
///   * per-client privacy budget: epsilon is recomputed ON-CHAIN from the declared noise using an
///     RDP accountant in fixed point (logs are pre-computed constants), and clients that would exceed
///     their budget are refused
///   * commit-reveal randomness -> unpredictable audit selection (the beacon exists only after every
///     noise seed hash has been committed)
///   * Merkle root over the commitments to client updates
///   * reputation: one failed audit => ban
///   * survivor check: the server may not omit a client that marked itself as submitted
///   * model-hash registry
///
/// Heavy cryptography (the Pedersen homomorphic check of the aggregate) runs off-chain from the
/// commitments logged here; its verdict is posted by the server and anyone can recompute it.
contract PrivacyLedger {
    uint256 private constant S = 1e18;               // fixed-point scale
    uint256 private constant REP_START = 10000;      // basis points
    uint256 private constant REP_FAIL = 7000;
    uint256 private constant REP_PASS = 500;
    uint256 private constant REP_BAN = 4000;
    uint256 public constant UNLIMITED = type(uint256).max;

    address public owner;
    address public server;
    address public auditor;
    uint256 public auditPpm;                         // audit probability, parts per million
    // ---- cryptoeconomic layer (disabled when minStake == 0)
    uint256 public minStake;                         // wei a client must have staked to be admitted
    uint256 public slashAmount;                      // wei taken per failed audit
    uint256 public rewardPool;                       // slashed funds waiting to be shared among honest clients
    uint256 public serverBond;
    mapping(address => uint256) public stake;
    mapping(address => uint256) public credit;       // earned rewards
    mapping(uint256 => bool) public serverSlashed;

    uint256[] public alphas;                         // RDP orders, S-scaled
    int256[] public convConst;                       // log1p(-1/a) - (log(delta)+log(a))/(a-1), S-scaled

    struct Client {
        bool registered;
        bool banned;
        uint256 epsMax;                              // S-scaled, or UNLIMITED
        uint256 rep;
        uint256 rounds;
    }
    mapping(address => Client) public clients;
    /// Gaussian-mechanism RDP is linear in the order: rdp(alpha) = alpha * sum_r 1/(2 z_r^2).
    /// One number per client is therefore enough (S-scaled).
    mapping(address => uint256) public accInv;
    address[] public clientList;

    struct Intent {
        bool admitted;
        bool declared;
        bool revealed;
        bool committed;
        bool submitted;
        bool seen;
        uint8 nm;                                    // 0 = local noise, 1 = distributed noise
        uint256 sigma;                               // 1e9-scaled
        uint256 clip;                                // 1e9-scaled
        bytes32 seedHash;
        bytes32 nonceHash;
        bytes32 nonceKey;
        bytes32 commit;
    }

    struct Round {
        bool begun;
        bool beaconSet;
        bool rootSet;
        bool done;
        bool accepted;
        uint256 honestK;
        uint256 nRevealed;
        uint256 nSubmitted;
        uint256 nDeclared;
        uint256 nCommitted;
        bytes32 beacon;
        bytes32 root;
        bytes32 modelHash;
        address[] admitted;
        address[] auditSet;
    }

    mapping(uint256 => Round) private rounds;
    mapping(uint256 => mapping(address => Intent)) private intents;
    mapping(uint256 => bytes32) public models;       // round -> accepted model hash
    // on-chain check of the aggregate against the committed updates (small models)
    bytes public groupP;
    bytes public groupG;
    bytes[] public groupH;
    mapping(uint256 => uint8) public chainVerified;          // 0 = not run, 1 = passed, 2 = failed
    mapping(uint256 => bytes32) private verifiedSet;
    mapping(uint256 => mapping(address => bytes32)) public maskedHashOf;  // hash of the masked vector the client actually sent
    mapping(uint256 => mapping(address => bytes32)) public proofHashOf;   // round -> client -> hash of the norm proof bundle

    event Registered(address indexed client, uint256 epsMax);
    event Deposited(address indexed who, uint256 amount);
    event Slashed(address indexed who, uint256 amount, uint256 indexed round, bool forfeited);
    event Rewarded(address indexed client, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);
    event Refused(uint256 indexed round, address indexed client, uint8 reason); // 1 banned 2 budget 3 no-noise 4 unregistered
    event RoundBegun(uint256 indexed round, uint256 admittedCount);
    event IntentPosted(uint256 indexed round, address indexed client, uint256 sigma, bytes32 seedHash);
    event BadNonce(uint256 indexed round, address indexed client);
    event BeaconSet(uint256 indexed round, bytes32 beacon);
    event Committed(uint256 indexed round, address indexed client, bytes commitment);
    event RootClosed(uint256 indexed round, bytes32 root);
    event ProofPosted(uint256 indexed round, address indexed client, bytes32 proofHash);
    event AuditSelected(uint256 indexed round, address[] set);
    event AuditResult(uint256 indexed round, address indexed client, bool ok, string reason, uint256 rep, bool banned);
    event Submitted(uint256 indexed round, address indexed client, bytes32 maskedHash);
    event SurvivorMismatch(uint256 indexed round);
    event VerificationFailed(uint256 indexed round);
    event GateRejected(uint256 indexed round);
    event AggregateChecked(uint256 indexed round, bool ok, uint256 terms);
    event Aggregated(uint256 indexed round, bool accepted, bytes32 modelHash, bytes32 aggHash, bool emergency, uint256 n);

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    modifier onlyServer() { require(msg.sender == server, "server"); _; }
    modifier onlyAuditor() { require(msg.sender == auditor, "auditor"); _; }

    constructor(address _server, address _auditor, uint256[] memory _alphas, int256[] memory _conv, uint256 _auditPpm,
                uint256 _minStake, uint256 _slashAmount) {
        require(_alphas.length == _conv.length && _alphas.length > 0, "alphas");
        owner = msg.sender;
        server = _server;
        auditor = _auditor;
        alphas = _alphas;
        convConst = _conv;
        auditPpm = _auditPpm;
        minStake = _minStake;
        slashAmount = _slashAmount;
    }

    // ------------------------------------------------------------------ registry
    function register(address c, uint256 epsMax) external onlyOwner {
        require(!clients[c].registered, "exists");
        clients[c] = Client(true, false, epsMax, REP_START, 0);
        clientList.push(c);
        emit Registered(c, epsMax);
    }

    // ------------------------------------------------------------------ stake, slashing, rewards
    function deposit() external payable {
        require(clients[msg.sender].registered, "register first");
        stake[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function postServerBond() external payable onlyServer {
        serverBond += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function _slash(address c, uint256 r) internal {
        if (minStake == 0) return;
        uint256 s = stake[c];
        bool forfeit = clients[c].banned;                 // a ban forfeits the whole remaining stake
        uint256 take = forfeit ? s : (s < slashAmount ? s : slashAmount);
        if (take == 0) return;
        stake[c] = s - take;
        rewardPool += take;
        emit Slashed(c, take, r, forfeit);
    }

    /// @notice Auditor attests that the server (not a client) caused a failed round, e.g. after the blame phase.
    function slashServer(uint256 r) external onlyAuditor {
        require(rounds[r].done && !rounds[r].accepted && !serverSlashed[r], "state");
        serverSlashed[r] = true;
        uint256 take = serverBond < slashAmount ? serverBond : slashAmount;
        serverBond -= take;
        rewardPool += take;
        emit Slashed(server, take, r, false);
    }

    /// @notice Share the slashed funds among clients that are not banned, in proportion to rounds taken part in.
    function distributeRewards() external onlyOwner {
        uint256 total;
        for (uint256 i = 0; i < clientList.length; i++) {
            Client storage c = clients[clientList[i]];
            if (!c.banned) total += c.rounds;
        }
        require(total > 0 && rewardPool > 0, "nothing to share");
        uint256 pool = rewardPool;
        rewardPool = 0;
        for (uint256 i = 0; i < clientList.length; i++) {
            address a = clientList[i];
            Client storage c = clients[a];
            if (c.banned || c.rounds == 0) continue;
            uint256 share = pool * c.rounds / total;
            credit[a] += share;
            emit Rewarded(a, share);
        }
    }

    /// @notice Honest clients take back their stake plus rewards (banned clients have nothing left).
    function withdraw() external {
        uint256 amt = stake[msg.sender] + credit[msg.sender];
        require(amt > 0, "nothing");
        stake[msg.sender] = 0;
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amt}("");
        require(ok, "transfer");
        emit Withdrawn(msg.sender, amt);
    }

    function setAuditRate(uint256 ppm) external onlyOwner {
        require(ppm <= 1_000_000, "ppm");
        auditPpm = ppm;
    }

    // ------------------------------------------------------------------ privacy accountant (fixed point)
    /// @dev 1/(2 z^2) with z = sigma*sqrt(k)/clip  =>  clip^2 / (2 sigma^2 k)
    function _inv2z2(uint256 sigma, uint256 clip, uint8 nm, uint256 k) internal pure returns (uint256) {
        if (sigma == 0) return 0;
        uint256 kk = nm == 0 ? 1 : (k == 0 ? 1 : k);
        return (clip * clip * S) / (2 * sigma * sigma * kk);
    }

    function _eps(address c, uint256 extra) internal view returns (uint256) {
        if (clients[c].rounds == 0 && extra == 0) return 0;
        uint256 total = accInv[c] + extra;
        int256 best = type(int256).max;
        for (uint256 i = 0; i < alphas.length; i++) {
            int256 v = int256((alphas[i] * total) / S) + convConst[i];
            if (v < best) best = v;
        }
        return best < 0 ? 0 : uint256(best);
    }

    /// @notice epsilon spent so far by `c` (S-scaled)
    function epsilon(address c) external view returns (uint256) { return _eps(c, 0); }

    // ------------------------------------------------------------------ round lifecycle
    /// @notice Server opens a round. Each candidate's declared noise is checked against its budget.
    function beginRound(
        uint256 r, address[] calldata cands, uint256[] calldata sigmas,
        uint256 clip, uint8 nm, uint256 honestK
    ) external onlyServer {
        Round storage R = rounds[r];
        require(!R.begun, "round exists");
        require(cands.length == sigmas.length, "len");
        R.begun = true;
        R.honestK = honestK;
        for (uint256 i = 0; i < cands.length; i++) {
            address c = cands[i];
            uint8 reason = _admission(c, sigmas[i], clip, nm, honestK);
            if (reason == 0) {
                R.admitted.push(c);
                Intent storage I = intents[r][c];
                I.admitted = true;
                I.sigma = sigmas[i];
                I.clip = clip;
                I.nm = nm;
            } else {
                emit Refused(r, c, reason);
            }
        }
        emit RoundBegun(r, R.admitted.length);
    }

    function _admission(address c, uint256 sigma, uint256 clip, uint8 nm, uint256 k) internal view returns (uint8) {
        Client storage cl = clients[c];
        if (!cl.registered) return 4;
        if (cl.banned) return 1;
        if (minStake > 0 && stake[c] < minStake) return 5;
        if (sigma == 0) return cl.epsMax == UNLIMITED ? 0 : 3;
        if (_eps(c, _inv2z2(sigma, clip, nm, k)) > cl.epsMax) return 2;
        return 0;
    }

    /// @notice Client declares its noise (must equal what was admitted) and commits to its noise seed + a beacon nonce.
    function postIntent(uint256 r, uint256 sigma, bytes32 seedHash, bytes32 nonceHash) external {
        Intent storage I = intents[r][msg.sender];
        require(I.admitted && !I.declared, "not admitted");
        require(sigma == I.sigma, "sigma differs from admitted");
        I.declared = true;
        rounds[r].nDeclared++;
        I.seedHash = seedHash;
        I.nonceHash = nonceHash;
        emit IntentPosted(r, msg.sender, sigma, seedHash);
    }

    function revealNonce(uint256 r, bytes calldata nonce) external {
        Intent storage I = intents[r][msg.sender];
        require(I.declared && !I.revealed, "state");
        if (sha256(nonce) != I.nonceHash) {
            emit BadNonce(r, msg.sender);
            return;
        }
        I.nonceKey = keccak256(nonce);
        I.revealed = true;
        rounds[r].nRevealed++;
    }

    /// @notice Public randomness from the revealed nonces. Noise seeds were fixed before this existed.
    function closeReveals(uint256 r) external {
        Round storage R = rounds[r];
        require(R.begun && !R.beaconSet, "state");
        bytes32 b;
        for (uint256 i = 0; i < R.admitted.length; i++) {
            Intent storage I = intents[r][R.admitted[i]];
            if (I.revealed) b = keccak256(abi.encodePacked(b, I.nonceKey));
        }
        R.beacon = b;
        R.beaconSet = true;
        emit BeaconSet(r, b);
    }

    /// @notice Client posts its Pedersen commitment (full bytes go to the log, hash to storage).
    function postCommitment(uint256 r, bytes calldata commitment) external {
        Round storage R = rounds[r];
        Intent storage I = intents[r][msg.sender];
        require(R.beaconSet && I.revealed && !I.committed, "state");
        I.commit = keccak256(commitment);
        I.committed = true;
        R.nCommitted++;
        emit Committed(r, msg.sender, commitment);
    }

    /// @notice Hash of the (off-chain) zero-knowledge norm-proof bundle; binds the client to the proof it published.
    function postProof(uint256 r, bytes32 proofHash) external {
        require(intents[r][msg.sender].committed, "state");
        proofHashOf[r][msg.sender] = proofHash;
        emit ProofPosted(r, msg.sender, proofHash);
    }

    function _leaf(address c, Intent storage I) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(c, I.commit, I.sigma, I.seedHash));
    }

    function closeCommitments(uint256 r) external {
        Round storage R = rounds[r];
        require(R.beaconSet && !R.rootSet, "state");
        uint256 n;
        for (uint256 i = 0; i < R.admitted.length; i++) if (intents[r][R.admitted[i]].committed) n++;
        bytes32[] memory level = new bytes32[](n);
        uint256 k;
        for (uint256 i = 0; i < R.admitted.length; i++) {
            address c = R.admitted[i];
            if (intents[r][c].committed) level[k++] = _leaf(c, intents[r][c]);
        }
        R.root = _merkle(level);
        R.rootSet = true;
        emit RootClosed(r, R.root);
    }

    function _merkle(bytes32[] memory level) internal pure returns (bytes32) {
        if (level.length == 0) return keccak256("");
        while (level.length > 1) {
            uint256 m = (level.length + 1) / 2;
            bytes32[] memory next = new bytes32[](m);
            for (uint256 j = 0; j < m; j++) {
                bytes32 left = level[2 * j];
                bytes32 right = (2 * j + 1 < level.length) ? level[2 * j + 1] : left;
                next[j] = keccak256(abi.encodePacked(left, right));
            }
            level = next;
        }
        return level[0];
    }

    /// @notice Audit set = hash(beacon, root) thresholded per client. Nobody controls it alone.
    function selectAudits(uint256 r) external {
        Round storage R = rounds[r];
        require(R.rootSet && R.auditSet.length == 0, "state");
        bytes32 seed = keccak256(abi.encodePacked(R.beacon, R.root));
        for (uint256 i = 0; i < R.admitted.length; i++) {
            address c = R.admitted[i];
            if (!intents[r][c].committed) continue;
            if (uint256(keccak256(abi.encodePacked(seed, c))) % 1_000_000 < auditPpm) R.auditSet.push(c);
        }
        emit AuditSelected(r, R.auditSet);
    }

    function reportAudit(uint256 r, address c, bool ok, string calldata reason) external onlyAuditor {
        Client storage cl = clients[c];
        if (ok) {
            cl.rep = cl.rep + REP_PASS > REP_START ? REP_START : cl.rep + REP_PASS;
        } else {
            cl.rep = cl.rep > REP_FAIL ? cl.rep - REP_FAIL : 0;
            if (cl.rep < REP_BAN) cl.banned = true;
            _slash(c, r);
        }
        emit AuditResult(r, c, ok, reason, cl.rep, cl.banned);
    }

    /// @param maskedHash hash of the masked vector sent to the server: the client's signed statement of what it sent,
    ///        so the server cannot later swap it and the blame phase can authenticate the vectors.
    function markSubmitted(uint256 r, bytes32 maskedHash) external {
        Intent storage I = intents[r][msg.sender];
        require(I.committed && !I.submitted, "state");
        I.submitted = true;
        maskedHashOf[r][msg.sender] = maskedHash;
        rounds[r].nSubmitted++;
        emit Submitted(r, msg.sender, maskedHash);
    }

    /// @notice Server posts the round result. The survivor set must equal the set of clients that marked
    ///         themselves submitted; `verified` is the outcome of the off-chain commitment check.
    ///         Every submitted client is charged, accepted or not (the noisy sum was released).
    /// @param flags bit0 = commitment check passed, bit1 = emergency audit ran, bit2 = quality gate passed
    function postAggregate(
        uint256 r, address[] calldata survivors, bytes32 modelHash, bytes32 aggHash, uint8 flags
    ) external onlyServer {
        Round storage R = rounds[r];
        require(R.begun && !R.done, "state");
        bool ok = _survivorsMatch(r, survivors);
        if (!ok) emit SurvivorMismatch(r);
        bool verified = flags & 1 != 0;
        if (chainVerified[r] != 0) {                       // the contract's own check overrides the server's claim
            verified = chainVerified[r] == 1 && verifiedSet[r] == keccak256(abi.encodePacked(survivors));
        }
        if (!verified) {
            emit VerificationFailed(r);
            ok = false;
        }
        if (flags & 4 == 0) {
            emit GateRejected(r);
            ok = false;
        }
        _charge(r);
        R.done = true;
        R.accepted = ok;
        if (ok) {
            R.modelHash = modelHash;
            models[r] = modelHash;
        }
        emit Aggregated(r, ok, modelHash, aggHash, flags & 2 != 0, R.nSubmitted);
    }

    function _survivorsMatch(uint256 r, address[] calldata survivors) internal returns (bool ok) {
        Round storage R = rounds[r];
        ok = survivors.length == R.nSubmitted;
        for (uint256 i = 0; i < survivors.length; i++) {
            Intent storage I = intents[r][survivors[i]];
            if (!I.submitted || I.seen) ok = false;
            I.seen = true;
        }
        for (uint256 i = 0; i < survivors.length; i++) intents[r][survivors[i]].seen = false;
    }

    function _charge(uint256 r) internal {
        Round storage R = rounds[r];
        uint256 k = R.nSubmitted < R.honestK ? R.nSubmitted : R.honestK;
        for (uint256 i = 0; i < R.admitted.length; i++) {
            address c = R.admitted[i];
            Intent storage I = intents[r][c];
            if (!I.submitted) continue;
            uint256 inc = _inv2z2(I.sigma, I.clip, I.nm, k);
            if (inc > 0) accInv[c] += inc;
            clients[c].rounds++;
        }
    }

    // ------------------------------------------------------------------ on-chain homomorphic check
    function setGroup(bytes calldata p, bytes calldata g, bytes[] calldata hs) external onlyOwner {
        require(groupP.length == 0, "set");
        groupP = p;
        groupG = g;
        for (uint256 i = 0; i < hs.length; i++) groupH.push(hs[i]);
    }

    /// @notice The contract itself checks   prod_u C_u  ==  g^R * prod_i h_i^{X_i}   (Pedersen homomorphism), so the
    ///         aggregate is exactly the sum of the committed updates - no trust in the server's verdict.
    ///         Costs ~(d+1) modexp calls: practical for small models only.
    function verifyAggregate(
        uint256 r, address[] calldata survivors, bytes[] calldata commits, uint256[] calldata X, uint256 Rsum
    ) external onlyServer returns (bool ok) {
        require(rounds[r].begun && chainVerified[r] == 0, "state");
        require(survivors.length == commits.length && survivors.length > 0 && X.length <= groupH.length, "len");
        bytes memory pB = groupP;
        uint256[4] memory p = Big.fromBytes(pB);
        uint256[4] memory lhs = _loadCommit(r, survivors[0], commits[0]);
        for (uint256 i = 1; i < survivors.length; i++) {
            lhs = Big.mulmod_(lhs, _loadCommit(r, survivors[i], commits[i]), p, pB);
        }
        uint256[4] memory rhs = Big.fromBytes(Big.modexp(groupG, abi.encodePacked(Rsum), pB));
        for (uint256 j = 0; j < X.length; j++) {
            if (X[j] == 0) continue;
            rhs = Big.mulmod_(rhs, Big.fromBytes(Big.modexp(groupH[j], abi.encodePacked(X[j]), pB)), p, pB);
        }
        ok = Big.cmp(lhs, rhs) == 0;
        chainVerified[r] = ok ? 1 : 2;
        verifiedSet[r] = keccak256(abi.encodePacked(survivors));
        emit AggregateChecked(r, ok, survivors.length);
    }

    /// @dev commitment bytes must match the hash the client posted
    function _loadCommit(uint256 r, address c, bytes calldata raw) internal view returns (uint256[4] memory) {
        require(raw.length == 128 && keccak256(raw) == intents[r][c].commit, "commitment mismatch");
        return Big.fromBytes(raw);
    }

    // ------------------------------------------------------------------ views
    function getAdmitted(uint256 r) external view returns (address[] memory) { return rounds[r].admitted; }
    /// @notice progress counters, so any party can see which phase of round r the chain is in
    function stats(uint256 r) external view returns (uint256 admitted, uint256 declared, uint256 revealed,
                                                     uint256 committed, uint256 submitted, bool beaconSet, bool rootSet, bool done) {
        Round storage R = rounds[r];
        return (R.admitted.length, R.nDeclared, R.nRevealed, R.nCommitted, R.nSubmitted, R.beaconSet, R.rootSet, R.done);
    }
    function getAuditSet(uint256 r) external view returns (address[] memory) { return rounds[r].auditSet; }
    function getBeacon(uint256 r) external view returns (bytes32) { return rounds[r].beacon; }
    function getRoot(uint256 r) external view returns (bytes32) { return rounds[r].root; }
    function commitHashOf(uint256 r, address c) external view returns (bytes32) { return intents[r][c].commit; }
    function isAccepted(uint256 r) external view returns (bool) { return rounds[r].accepted; }
    function nSubmitted(uint256 r) external view returns (uint256) { return rounds[r].nSubmitted; }
    function alphaCount() external view returns (uint256) { return alphas.length; }
}
