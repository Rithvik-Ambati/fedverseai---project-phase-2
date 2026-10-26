/** Hardhat config: a local permissioned-style chain with enough funded accounts for 32 clients + roles. */
module.exports = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: { count: 60 },
      blockGasLimit: 60000000,
      allowUnlimitedContractSize: false,
    },
  },
};
