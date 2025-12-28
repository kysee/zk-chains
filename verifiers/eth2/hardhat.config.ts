import { defineConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-viem";
import "@nomicfoundation/hardhat-network-helpers";
import "@nomicfoundation/hardhat-mocha";

export default defineConfig({
    solidity: {
        version: "0.8.28",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
    }
});
