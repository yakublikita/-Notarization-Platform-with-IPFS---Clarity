# 📜 Notarization Platform with IPFS & Clarity

> Secure, decentralized document notarization using IPFS and Stacks blockchain

## 🎯 Overview

This smart contract enables trustless document notarization by storing IPFS content hashes on the Stacks blockchain. Users can:

- 📄 Notarize documents by storing their IPFS hashes
- ⏰ Get blockchain-based timestamps for proof of existence
- 🔒 Control document access with private/public settings
- 👥 Grant/revoke access to specific users
- ✅ Verify document authenticity using stored hashes

## 📚 Contract Functions

### Notarize Document
```clarity
(notarize-document hash title description is-private)
```

### Access Control
```clarity
(grant-access hash viewer)
(revoke-access hash viewer)
```

### View Functions
```clarity
(get-document-info hash)
(can-view-document hash viewer)
(get-total-documents)
```

## 🚀 Getting Started

1. Deploy the contract using Clarinet
2. Upload document to IPFS and get content hash
3. Call `notarize-document` with the IPFS hash
4. Share document hash for verification

## 🔐 Security

- Document hashes are immutable once stored
- Access controls for private documents
- Owner-only permission management

## 📋 Requirements

- Clarinet
- IPFS node/gateway
- Stacks wallet
```
