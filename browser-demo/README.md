# Browser Voting Demo

Interactive browser demo for FHE voting with Web2 and Web3 modes. Cast an encrypted vote, run the tally computation on encrypted data, and see results without exposing individual votes.

## Prerequisites

Build the TypeScript library first:

```sh
cd ../typescript
npm install
npm run build
cd ../browser-demo
```

## Running the Demo

```sh
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## What It Demonstrates

The demo showcases two signing modes:

- Web2 Mode: Generates ephemeral keys in the browser for testing
- Web3 Mode: Uses MetaMask for user operations

Workflow:
- Cast a vote (approve/reject)
- Demo generates 8 additional simulated votes
- All votes are encrypted client-side with FHE
- Runner executes the voting program on encrypted data
- Result is decrypted via threshold decryption
- Final tally (approved/rejected) is displayed

## Learn More

See [docs.sunscreen.tech](https://docs.sunscreen.tech) for complete documentation on FHE programming with SPF.
