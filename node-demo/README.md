# Node.js Voting Demo

Backend voting example demonstrating FHE. Four voters submit encrypted votes, a runner executes the encrypted tally computation, and the result is decrypted without exposing individual votes.

## Prerequisites

Build the TypeScript library first:

```sh
cd ../typescript
npm install
npm run build
cd ../node-demo
```

## Running the Demo

```sh
npm install
npm run voting
```

## What Happens

The demo simulates a complete voting workflow:

- Four voters encrypt their votes (approve/reject) client-side
- Each voter uploads their encrypted vote to the SPF service
- Voters grant run access to the runner for the voting program
- Runner submits the FHE computation to tally all votes
- Runner requests threshold decryption of the encrypted result
- Final outcome (approved/rejected) is displayed

## Example Output

```
Run submitted: 0x...
Run status: success
Result ciphertext ID: 0x...
Decrypt access granted
Decryption requested: 0x...
Decrypted plaintext: 1
Voting Result: Approved
```

With votes [approve, reject, approve, approve], the result is approved.

## Learn More

See [docs.sunscreen.tech](https://docs.sunscreen.tech) for complete documentation on FHE programming with SPF.
