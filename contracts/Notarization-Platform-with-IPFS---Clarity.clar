(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-HASH (err u101))
(define-constant ERR-DOCUMENT-EXISTS (err u102))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u103))
(define-constant ERR-INVALID-OWNER (err u104))

(define-map documents 
    { hash: (string-ascii 64) }
    { 
        owner: principal,
        timestamp: uint,
        title: (string-ascii 64),
        description: (string-ascii 256),
        is-private: bool
    }
)

(define-map document-access
    { hash: (string-ascii 64), viewer: principal }
    { can-view: bool }
)

(define-data-var total-documents uint u0)

(define-public (notarize-document 
    (hash (string-ascii 64))
    (title (string-ascii 64))
    (description (string-ascii 256))
    (is-private bool))
    (let
        ((existing-doc (get-document-info hash)))
        (asserts! (is-none existing-doc) ERR-DOCUMENT-EXISTS)
        (try! (validate-hash hash))
        (map-set documents
            { hash: hash }
            {
                owner: tx-sender,
                timestamp: stacks-block-height,
                title: title,
                description: description,
                is-private: is-private
            }
        )
        (var-set total-documents (+ (var-get total-documents) u1))
        (ok true)
    )
)

(define-public (grant-access 
    (hash (string-ascii 64))
    (viewer principal))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND)))
        (asserts! (is-eq (get owner doc-info) tx-sender) ERR-NOT-AUTHORIZED)
        (map-set document-access
            { hash: hash, viewer: viewer }
            { can-view: true }
        )
        (ok true)
    )
)

(define-public (revoke-access
    (hash (string-ascii 64))
    (viewer principal))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND)))
        (asserts! (is-eq (get owner doc-info) tx-sender) ERR-NOT-AUTHORIZED)
        (map-set document-access
            { hash: hash, viewer: viewer }
            { can-view: false }
        )
        (ok true)
    )
)

(define-read-only (get-document-info (hash (string-ascii 64)))
    (map-get? documents { hash: hash })
)

(define-read-only (can-view-document 
    (hash (string-ascii 64))
    (viewer principal))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND)))
        (ok (or
            (is-eq (get owner doc-info) viewer)
            (not (get is-private doc-info))
            (default-to 
                false
                (get can-view (map-get? document-access { hash: hash, viewer: viewer })))
        ))
    )
)

(define-read-only (get-total-documents)
    (ok (var-get total-documents))
)

(define-private (validate-hash (hash (string-ascii 64)))
    (if (is-eq (len hash) u64)
        (ok true)
        ERR-INVALID-HASH
    )
)

(define-constant ERR-NOT-VERIFIER (err u200))
(define-constant ERR-ALREADY-VERIFIED (err u201))
(define-constant ERR-VERIFICATION-NOT-FOUND (err u202))
(define-constant ERR-CANNOT-VERIFY-OWN (err u203))

(define-map verifiers
    { verifier: principal }
    { 
        is-active: bool,
        reputation-score: uint,
        total-verifications: uint
    }
)

(define-map document-verifications
    { hash: (string-ascii 64), verifier: principal }
    {
        verified: bool,
        verification-timestamp: uint,
        verification-notes: (string-ascii 256)
    }
)

(define-map verification-summary
    { hash: (string-ascii 64) }
    {
        total-verifications: uint,
        positive-verifications: uint,
        verification-score: uint
    }
)

(define-data-var contract-owner principal tx-sender)

(define-public (add-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set verifiers
            { verifier: verifier }
            {
                is-active: true,
                reputation-score: u100,
                total-verifications: u0
            }
        )
        (ok true)
    )
)

(define-public (verify-document
    (hash (string-ascii 64))
    (is-verified bool)
    (notes (string-ascii 256)))
    (let
        ((verifier-info (unwrap! (map-get? verifiers { verifier: tx-sender }) ERR-NOT-VERIFIER))
         (doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (existing-verification (map-get? document-verifications { hash: hash, verifier: tx-sender })))
        (asserts! (get is-active verifier-info) ERR-NOT-VERIFIER)
        (asserts! (not (is-eq tx-sender (get owner doc-info))) ERR-CANNOT-VERIFY-OWN)
        (asserts! (is-none existing-verification) ERR-ALREADY-VERIFIED)
        (map-set document-verifications
            { hash: hash, verifier: tx-sender }
            {
                verified: is-verified,
                verification-timestamp: stacks-block-height,
                verification-notes: notes
            }
        )
        (unwrap-panic (update-verification-summary hash is-verified))
        (unwrap-panic (update-verifier-stats tx-sender))
        (ok true)
    )
)

(define-public (remove-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set verifiers
            { verifier: verifier }
            {
                is-active: false,
                reputation-score: u0,
                total-verifications: u0
            }
        )
        (ok true)
    )
)

(define-read-only (get-document-verification-score (hash (string-ascii 64)))
    (ok (map-get? verification-summary { hash: hash }))
)

(define-read-only (get-verifier-info (verifier principal))
    (ok (map-get? verifiers { verifier: verifier }))
)

(define-read-only (get-document-verification
    (hash (string-ascii 64))
    (verifier principal))
    (ok (map-get? document-verifications { hash: hash, verifier: verifier }))
)

(define-private (update-verification-summary (hash (string-ascii 64)) (is-positive bool))
    (let
        ((current-summary (default-to 
            { total-verifications: u0, positive-verifications: u0, verification-score: u0 }
            (map-get? verification-summary { hash: hash })))
         (new-total (+ (get total-verifications current-summary) u1))
         (new-positive (if is-positive 
            (+ (get positive-verifications current-summary) u1)
            (get positive-verifications current-summary)))
         (new-score (if (> new-total u0) (/ (* new-positive u100) new-total) u0)))
        (begin
            (map-set verification-summary
                { hash: hash }
                {
                    total-verifications: new-total,
                    positive-verifications: new-positive,
                    verification-score: new-score
                }
            )
            (ok true)
        )
    )
)

(define-private (update-verifier-stats (verifier principal))
    (let
        ((verifier-info (unwrap! (map-get? verifiers { verifier: verifier }) ERR-NOT-VERIFIER))
         (new-total (+ (get total-verifications verifier-info) u1))
         (new-reputation (+ (get reputation-score verifier-info) u1)))
        (begin
            (map-set verifiers
                { verifier: verifier }
                {
                    is-active: (get is-active verifier-info),
                    reputation-score: new-reputation,
                    total-verifications: new-total
                }
            )
            (ok true)
        )
    )
)

(define-constant ERR-DOCUMENT-EXPIRED (err u300))
(define-constant ERR-INVALID-EXPIRATION (err u301))
(define-constant ERR-RENEWAL-NOT-ALLOWED (err u302))
(define-constant ERR-EXPIRATION-NOT-SET (err u303))

(define-constant ERR-INVALID-CATEGORY (err u400))
(define-constant ERR-CATEGORY-NOT-FOUND (err u401))
(define-constant ERR-CATEGORY-EXISTS (err u402))

(define-map document-expiration
    { hash: (string-ascii 64) }
    {
        expiration-block: uint,
        is-renewable: bool,
        renewal-count: uint,
        max-renewals: uint,
        renewal-period: uint
    }
)

(define-map renewal-history
    { hash: (string-ascii 64), renewal-id: uint }
    {
        renewed-at: uint,
        renewed-by: principal,
        previous-expiration: uint,
        new-expiration: uint
    }
)

(define-data-var default-expiration-period uint u52560)

(define-map document-categories
    { hash: (string-ascii 64) }
    { category: (string-ascii 32) }
)

(define-map category-documents
    { category: (string-ascii 32), hash: (string-ascii 64) }
    { exists: bool }
)

(define-data-var total-categories uint u0)
(define-public (set-document-expiration
    (hash (string-ascii 64))
    (expiration-blocks uint)
    (is-renewable bool)
    (max-renewals uint)
    (renewal-period uint))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (expiration-block (+ stacks-block-height expiration-blocks)))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (> expiration-blocks u0) ERR-INVALID-EXPIRATION)
        (map-set document-expiration
            { hash: hash }
            {
                expiration-block: expiration-block,
                is-renewable: is-renewable,
                renewal-count: u0,
                max-renewals: max-renewals,
                renewal-period: renewal-period
            }
        )
        (ok expiration-block)
    )
)

(define-public (renew-document (hash (string-ascii 64)))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
          (expiration-info (unwrap! (map-get? document-expiration { hash: hash }) ERR-EXPIRATION-NOT-SET))
          (current-block stacks-block-height)
          (new-expiration (+ current-block (get renewal-period expiration-info)))
          (new-renewal-count (+ (get renewal-count expiration-info) u1)))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (get is-renewable expiration-info) ERR-RENEWAL-NOT-ALLOWED)
        (asserts! (< (get renewal-count expiration-info) (get max-renewals expiration-info)) ERR-RENEWAL-NOT-ALLOWED)
        (map-set renewal-history
            { hash: hash, renewal-id: new-renewal-count }
            {
                renewed-at: current-block,
                renewed-by: tx-sender,
                previous-expiration: (get expiration-block expiration-info),
                new-expiration: new-expiration
            }
        )
        (map-set document-expiration
            { hash: hash }
            {
                expiration-block: new-expiration,
                is-renewable: (get is-renewable expiration-info),
                renewal-count: new-renewal-count,
                max-renewals: (get max-renewals expiration-info),
                renewal-period: (get renewal-period expiration-info)
            }
        )
        (ok new-expiration)
    )
)

(define-public (extend-document-expiration
    (hash (string-ascii 64))
    (additional-blocks uint))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
          (expiration-info (unwrap! (map-get? document-expiration { hash: hash }) ERR-EXPIRATION-NOT-SET))
          (new-expiration (+ (get expiration-block expiration-info) additional-blocks)))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (> additional-blocks u0) ERR-INVALID-EXPIRATION)
        (map-set document-expiration
            { hash: hash }
            {
                expiration-block: new-expiration,
                is-renewable: (get is-renewable expiration-info),
                renewal-count: (get renewal-count expiration-info),
                max-renewals: (get max-renewals expiration-info),
                renewal-period: (get renewal-period expiration-info)
            }
        )
        (ok new-expiration)
    )
)

(define-read-only (is-document-valid (hash (string-ascii 64)))
    (match (map-get? document-expiration { hash: hash })
        expiration-info (ok (> (get expiration-block expiration-info) stacks-block-height))
        (ok true)
    )
)

(define-read-only (get-document-expiration (hash (string-ascii 64)))
    (ok (map-get? document-expiration { hash: hash }))
)

(define-read-only (get-renewal-history
    (hash (string-ascii 64))
    (renewal-id uint))
    (ok (map-get? renewal-history { hash: hash, renewal-id: renewal-id }))
)

(define-read-only (get-expiring-documents-count (blocks-ahead uint))
    (ok blocks-ahead)
)

(define-read-only (can-renew-document (hash (string-ascii 64)))
    (match (map-get? document-expiration { hash: hash })
        expiration-info (ok (and 
            (get is-renewable expiration-info)
            (< (get renewal-count expiration-info) (get max-renewals expiration-info))))
        (ok false)
    )
)

(define-public (set-default-expiration-period (blocks uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> blocks u0) ERR-INVALID-EXPIRATION)
        (var-set default-expiration-period blocks)
        (ok true)
    )
)

(define-read-only (get-default-expiration-period)
    (ok (var-get default-expiration-period))
)

(define-public (set-document-category
    (hash (string-ascii 64))
    (category (string-ascii 32)))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (existing-category (map-get? document-categories { hash: hash })))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (> (len category) u0) ERR-INVALID-CATEGORY)
        (asserts! (<= (len category) u32) ERR-INVALID-CATEGORY)
        (if (is-some existing-category)
            (let ((old-category (get category (unwrap-panic existing-category))))
                (map-delete category-documents { category: old-category, hash: hash }))
            (var-set total-categories (+ (var-get total-categories) u1)))
        (map-set document-categories
            { hash: hash }
            { category: category })
        (map-set category-documents
            { category: category, hash: hash }
            { exists: true })
        (ok true)
    )
)

(define-public (remove-document-category (hash (string-ascii 64)))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (category-info (unwrap! (map-get? document-categories { hash: hash }) ERR-CATEGORY-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (map-delete document-categories { hash: hash })
        (map-delete category-documents { category: (get category category-info), hash: hash })
        (var-set total-categories (- (var-get total-categories) u1))
        (ok true)
    )
)

(define-read-only (get-document-category (hash (string-ascii 64)))
    (ok (map-get? document-categories { hash: hash }))
)

(define-read-only (is-document-in-category
    (hash (string-ascii 64))
    (category (string-ascii 32)))
    (ok (is-some (map-get? category-documents { category: category, hash: hash })))
)

(define-read-only (get-total-categories)
    (ok (var-get total-categories))
)

(define-private (validate-category (category (string-ascii 32)))
    (if (and (> (len category) u0) (<= (len category) u32))
        (ok true)
        ERR-INVALID-CATEGORY)
)

(define-constant ERR-AMENDMENT-NOT-FOUND (err u500))
(define-constant ERR-INVALID-AMENDMENT-REASON (err u501))
(define-constant ERR-MAX-AMENDMENTS-REACHED (err u502))
(define-constant ERR-INVALID-AMENDMENT-HASH (err u503))

(define-map document-amendments
    { original-hash: (string-ascii 64), amendment-id: uint }
    {
        amendment-hash: (string-ascii 64),
        amended-by: principal,
        amendment-timestamp: uint,
        amendment-reason: (string-ascii 256),
        is-active: bool
    }
)

(define-map amendment-summary
    { hash: (string-ascii 64) }
    {
        total-amendments: uint,
        latest-amendment-hash: (string-ascii 64),
        latest-amendment-timestamp: uint,
        max-amendments-allowed: uint
    }
)

(define-data-var total-amendments uint u0)
(define-data-var default-max-amendments uint u10)

(define-public (create-amendment
    (original-hash (string-ascii 64))
    (amendment-hash (string-ascii 64))
    (amendment-reason (string-ascii 256)))
    (let
        ((doc-info (unwrap! (get-document-info original-hash) ERR-DOCUMENT-NOT-FOUND))
         (current-summary (default-to
            {
                total-amendments: u0,
                latest-amendment-hash: "",
                latest-amendment-timestamp: u0,
                max-amendments-allowed: (var-get default-max-amendments)
            }
            (map-get? amendment-summary { hash: original-hash })))
         (new-amendment-id (+ (get total-amendments current-summary) u1))
         (current-block stacks-block-height))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (> (len amendment-reason) u0) ERR-INVALID-AMENDMENT-REASON)
        (asserts! (<= (len amendment-reason) u256) ERR-INVALID-AMENDMENT-REASON)
        (try! (validate-hash amendment-hash))
        (asserts! (not (is-eq original-hash amendment-hash)) ERR-INVALID-AMENDMENT-HASH)
        (asserts! (< (get total-amendments current-summary) (get max-amendments-allowed current-summary)) ERR-MAX-AMENDMENTS-REACHED)
        (map-set document-amendments
            { original-hash: original-hash, amendment-id: new-amendment-id }
            {
                amendment-hash: amendment-hash,
                amended-by: tx-sender,
                amendment-timestamp: current-block,
                amendment-reason: amendment-reason,
                is-active: true
            }
        )
        (map-set amendment-summary
            { hash: original-hash }
            {
                total-amendments: new-amendment-id,
                latest-amendment-hash: amendment-hash,
                latest-amendment-timestamp: current-block,
                max-amendments-allowed: (get max-amendments-allowed current-summary)
            }
        )
        (var-set total-amendments (+ (var-get total-amendments) u1))
        (ok new-amendment-id)
    )
)

(define-public (set-max-amendments
    (hash (string-ascii 64))
    (max-amendments uint))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (current-summary (default-to
            {
                total-amendments: u0,
                latest-amendment-hash: "",
                latest-amendment-timestamp: u0,
                max-amendments-allowed: (var-get default-max-amendments)
            }
            (map-get? amendment-summary { hash: hash }))))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (>= max-amendments (get total-amendments current-summary)) ERR-INVALID-EXPIRATION)
        (map-set amendment-summary
            { hash: hash }
            {
                total-amendments: (get total-amendments current-summary),
                latest-amendment-hash: (get latest-amendment-hash current-summary),
                latest-amendment-timestamp: (get latest-amendment-timestamp current-summary),
                max-amendments-allowed: max-amendments
            }
        )
        (ok true)
    )
)

(define-read-only (get-document-amendment
    (original-hash (string-ascii 64))
    (amendment-id uint))
    (ok (map-get? document-amendments { original-hash: original-hash, amendment-id: amendment-id }))
)

(define-read-only (get-amendment-summary (hash (string-ascii 64)))
    (ok (map-get? amendment-summary { hash: hash }))
)

(define-read-only (get-latest-amendment (hash (string-ascii 64)))
    (match (map-get? amendment-summary { hash: hash })
        summary-info
            (if (> (get total-amendments summary-info) u0)
                (ok (map-get? document-amendments 
                    { original-hash: hash, amendment-id: (get total-amendments summary-info) }))
                (ok none))
        (ok none)
    )
)

(define-read-only (has-amendments (hash (string-ascii 64)))
    (match (map-get? amendment-summary { hash: hash })
        summary-info (ok (> (get total-amendments summary-info) u0))
        (ok false)
    )
)

(define-read-only (can-create-amendment (hash (string-ascii 64)))
    (match (map-get? amendment-summary { hash: hash })
        summary-info (ok (< (get total-amendments summary-info) (get max-amendments-allowed summary-info)))
        (ok true)
    )
)

(define-read-only (get-total-amendments)
    (ok (var-get total-amendments))
)

(define-public (set-default-max-amendments (max-amendments uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> max-amendments u0) ERR-INVALID-EXPIRATION)
        (var-set default-max-amendments max-amendments)
        (ok true)
    )
)

(define-read-only (get-default-max-amendments)
    (ok (var-get default-max-amendments))
)

(define-constant ERR-TRANSFER-NOT-FOUND (err u600))
(define-constant ERR-TRANSFER-EXISTS (err u601))
(define-constant ERR-NOT-TRANSFER-RECIPIENT (err u602))
(define-constant ERR-TRANSFER-EXPIRED (err u603))
(define-constant ERR-CANNOT-TRANSFER-TO-SELF (err u604))

(define-map ownership-transfers
    { hash: (string-ascii 64) }
    {
        from-owner: principal,
        to-owner: principal,
        initiated-at: uint,
        expiration-block: uint,
        is-pending: bool
    }
)

(define-map transfer-history
    { hash: (string-ascii 64), transfer-id: uint }
    {
        from-owner: principal,
        to-owner: principal,
        completed-at: uint,
        initiated-at: uint
    }
)

(define-map document-transfer-count
    { hash: (string-ascii 64) }
    { count: uint }
)

(define-data-var total-transfers uint u0)
(define-data-var transfer-expiration-blocks uint u1440)

(define-public (initiate-ownership-transfer
    (hash (string-ascii 64))
    (new-owner principal))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (existing-transfer (map-get? ownership-transfers { hash: hash }))
         (expiration-block (+ stacks-block-height (var-get transfer-expiration-blocks))))
        (asserts! (is-eq tx-sender (get owner doc-info)) ERR-NOT-AUTHORIZED)
        (asserts! (not (is-eq tx-sender new-owner)) ERR-CANNOT-TRANSFER-TO-SELF)
        (asserts! (is-none existing-transfer) ERR-TRANSFER-EXISTS)
        (map-set ownership-transfers
            { hash: hash }
            {
                from-owner: tx-sender,
                to-owner: new-owner,
                initiated-at: stacks-block-height,
                expiration-block: expiration-block,
                is-pending: true
            }
        )
        (ok true)
    )
)

(define-public (accept-ownership-transfer (hash (string-ascii 64)))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (transfer-info (unwrap! (map-get? ownership-transfers { hash: hash }) ERR-TRANSFER-NOT-FOUND))
         (current-count (default-to { count: u0 } (map-get? document-transfer-count { hash: hash })))
         (new-transfer-id (+ (get count current-count) u1)))
        (asserts! (get is-pending transfer-info) ERR-TRANSFER-NOT-FOUND)
        (asserts! (is-eq tx-sender (get to-owner transfer-info)) ERR-NOT-TRANSFER-RECIPIENT)
        (asserts! (<= stacks-block-height (get expiration-block transfer-info)) ERR-TRANSFER-EXPIRED)
        (map-set documents
            { hash: hash }
            {
                owner: tx-sender,
                timestamp: (get timestamp doc-info),
                title: (get title doc-info),
                description: (get description doc-info),
                is-private: (get is-private doc-info)
            }
        )
        (map-set transfer-history
            { hash: hash, transfer-id: new-transfer-id }
            {
                from-owner: (get from-owner transfer-info),
                to-owner: tx-sender,
                completed-at: stacks-block-height,
                initiated-at: (get initiated-at transfer-info)
            }
        )
        (map-set document-transfer-count
            { hash: hash }
            { count: new-transfer-id }
        )
        (map-delete ownership-transfers { hash: hash })
        (var-set total-transfers (+ (var-get total-transfers) u1))
        (ok true)
    )
)

(define-public (cancel-ownership-transfer (hash (string-ascii 64)))
    (let
        ((transfer-info (unwrap! (map-get? ownership-transfers { hash: hash }) ERR-TRANSFER-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get from-owner transfer-info)) ERR-NOT-AUTHORIZED)
        (asserts! (get is-pending transfer-info) ERR-TRANSFER-NOT-FOUND)
        (map-delete ownership-transfers { hash: hash })
        (ok true)
    )
)

(define-public (reject-ownership-transfer (hash (string-ascii 64)))
    (let
        ((transfer-info (unwrap! (map-get? ownership-transfers { hash: hash }) ERR-TRANSFER-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get to-owner transfer-info)) ERR-NOT-TRANSFER-RECIPIENT)
        (asserts! (get is-pending transfer-info) ERR-TRANSFER-NOT-FOUND)
        (map-delete ownership-transfers { hash: hash })
        (ok true)
    )
)

(define-read-only (get-pending-transfer (hash (string-ascii 64)))
    (ok (map-get? ownership-transfers { hash: hash }))
)

(define-read-only (has-pending-transfer (hash (string-ascii 64)))
    (match (map-get? ownership-transfers { hash: hash })
        transfer-info (ok (and 
            (get is-pending transfer-info)
            (<= stacks-block-height (get expiration-block transfer-info))))
        (ok false)
    )
)

(define-read-only (get-transfer-history
    (hash (string-ascii 64))
    (transfer-id uint))
    (ok (map-get? transfer-history { hash: hash, transfer-id: transfer-id }))
)

(define-read-only (get-document-transfer-count (hash (string-ascii 64)))
    (ok (default-to { count: u0 } (map-get? document-transfer-count { hash: hash })))
)

(define-read-only (get-total-transfers)
    (ok (var-get total-transfers))
)

(define-read-only (is-transfer-expired (hash (string-ascii 64)))
    (match (map-get? ownership-transfers { hash: hash })
        transfer-info (ok (> stacks-block-height (get expiration-block transfer-info)))
        (ok false)
    )
)

(define-public (set-transfer-expiration-blocks (blocks uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> blocks u0) ERR-INVALID-EXPIRATION)
        (var-set transfer-expiration-blocks blocks)
        (ok true)
    )
)

(define-read-only (get-transfer-expiration-blocks)
    (ok (var-get transfer-expiration-blocks))
)

(define-constant ERR-DISPUTE-EXISTS (err u700))
(define-constant ERR-DISPUTE-NOT-FOUND (err u701))
(define-constant ERR-DISPUTE-RESOLVED (err u702))
(define-constant ERR-NOT-ARBITRATOR (err u703))
(define-constant ERR-CANNOT-DISPUTE-OWN (err u704))
(define-constant ERR-INVALID-EVIDENCE (err u705))
(define-constant ERR-MAX-EVIDENCE-REACHED (err u706))
(define-constant ERR-DISPUTE-EXPIRED (err u707))
(define-constant ERR-INVALID-RESOLUTION (err u708))

(define-map disputes
    { hash: (string-ascii 64), dispute-id: uint }
    {
        disputer: principal,
        reason: (string-ascii 256),
        initiated-at: uint,
        status: (string-ascii 16),
        resolution: (string-ascii 256),
        arbitrator: (optional principal),
        resolved-at: uint,
        resolution-type: (string-ascii 16)
    }
)

(define-map dispute-evidence
    { hash: (string-ascii 64), dispute-id: uint, evidence-id: uint }
    {
        submitted-by: principal,
        evidence-hash: (string-ascii 64),
        evidence-description: (string-ascii 256),
        submitted-at: uint
    }
)

(define-map document-dispute-summary
    { hash: (string-ascii 64) }
    {
        total-disputes: uint,
        active-disputes: uint,
        resolved-disputes: uint,
        total-evidence-count: uint
    }
)

(define-map arbitrators
    { arbitrator: principal }
    {
        is-active: bool,
        cases-resolved: uint,
        reputation: uint
    }
)

(define-map evidence-count
    { hash: (string-ascii 64), dispute-id: uint }
    { count: uint }
)

(define-data-var total-disputes uint u0)
(define-data-var max-evidence-per-dispute uint u10)
(define-data-var dispute-expiration-blocks uint u2880)

(define-public (add-arbitrator (arbitrator principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set arbitrators
            { arbitrator: arbitrator }
            {
                is-active: true,
                cases-resolved: u0,
                reputation: u100
            }
        )
        (ok true)
    )
)

(define-public (remove-arbitrator (arbitrator principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (map-set arbitrators
            { arbitrator: arbitrator }
            {
                is-active: false,
                cases-resolved: u0,
                reputation: u0
            }
        )
        (ok true)
    )
)

(define-public (raise-dispute
    (hash (string-ascii 64))
    (reason (string-ascii 256)))
    (let
        ((doc-info (unwrap! (get-document-info hash) ERR-DOCUMENT-NOT-FOUND))
         (current-summary (default-to
            { total-disputes: u0, active-disputes: u0, resolved-disputes: u0, total-evidence-count: u0 }
            (map-get? document-dispute-summary { hash: hash })))
         (new-dispute-id (+ (get total-disputes current-summary) u1))
         (current-block stacks-block-height))
        (asserts! (not (is-eq tx-sender (get owner doc-info))) ERR-CANNOT-DISPUTE-OWN)
        (asserts! (> (len reason) u0) ERR-INVALID-EVIDENCE)
        (asserts! (<= (len reason) u256) ERR-INVALID-EVIDENCE)
        (map-set disputes
            { hash: hash, dispute-id: new-dispute-id }
            {
                disputer: tx-sender,
                reason: reason,
                initiated-at: current-block,
                status: "pending",
                resolution: "",
                arbitrator: none,
                resolved-at: u0,
                resolution-type: ""
            }
        )
        (map-set document-dispute-summary
            { hash: hash }
            {
                total-disputes: new-dispute-id,
                active-disputes: (+ (get active-disputes current-summary) u1),
                resolved-disputes: (get resolved-disputes current-summary),
                total-evidence-count: (get total-evidence-count current-summary)
            }
        )
        (var-set total-disputes (+ (var-get total-disputes) u1))
        (ok new-dispute-id)
    )
)

(define-public (submit-evidence
    (hash (string-ascii 64))
    (dispute-id uint)
    (evidence-hash (string-ascii 64))
    (evidence-description (string-ascii 256)))
    (let
        ((dispute-info (unwrap! (map-get? disputes { hash: hash, dispute-id: dispute-id }) ERR-DISPUTE-NOT-FOUND))
         (current-count (default-to { count: u0 } (map-get? evidence-count { hash: hash, dispute-id: dispute-id })))
         (new-evidence-id (+ (get count current-count) u1))
         (current-summary (unwrap! (map-get? document-dispute-summary { hash: hash }) ERR-DOCUMENT-NOT-FOUND))
         (current-block stacks-block-height))
        (asserts! (is-eq (get status dispute-info) "pending") ERR-DISPUTE-RESOLVED)
        (asserts! (< (get count current-count) (var-get max-evidence-per-dispute)) ERR-MAX-EVIDENCE-REACHED)
        (try! (validate-hash evidence-hash))
        (asserts! (> (len evidence-description) u0) ERR-INVALID-EVIDENCE)
        (map-set dispute-evidence
            { hash: hash, dispute-id: dispute-id, evidence-id: new-evidence-id }
            {
                submitted-by: tx-sender,
                evidence-hash: evidence-hash,
                evidence-description: evidence-description,
                submitted-at: current-block
            }
        )
        (map-set evidence-count
            { hash: hash, dispute-id: dispute-id }
            { count: new-evidence-id }
        )
        (map-set document-dispute-summary
            { hash: hash }
            {
                total-disputes: (get total-disputes current-summary),
                active-disputes: (get active-disputes current-summary),
                resolved-disputes: (get resolved-disputes current-summary),
                total-evidence-count: (+ (get total-evidence-count current-summary) u1)
            }
        )
        (ok new-evidence-id)
    )
)

(define-public (resolve-dispute
    (hash (string-ascii 64))
    (dispute-id uint)
    (resolution (string-ascii 256))
    (resolution-type (string-ascii 16)))
    (let
        ((dispute-info (unwrap! (map-get? disputes { hash: hash, dispute-id: dispute-id }) ERR-DISPUTE-NOT-FOUND))
         (arbitrator-info (unwrap! (map-get? arbitrators { arbitrator: tx-sender }) ERR-NOT-ARBITRATOR))
         (current-summary (unwrap! (map-get? document-dispute-summary { hash: hash }) ERR-DOCUMENT-NOT-FOUND))
         (current-block stacks-block-height))
        (asserts! (get is-active arbitrator-info) ERR-NOT-ARBITRATOR)
        (asserts! (is-eq (get status dispute-info) "pending") ERR-DISPUTE-RESOLVED)
        (asserts! (> (len resolution) u0) ERR-INVALID-RESOLUTION)
        (asserts! (or (is-eq resolution-type "upheld") (is-eq resolution-type "dismissed")) ERR-INVALID-RESOLUTION)
        (map-set disputes
            { hash: hash, dispute-id: dispute-id }
            {
                disputer: (get disputer dispute-info),
                reason: (get reason dispute-info),
                initiated-at: (get initiated-at dispute-info),
                status: "resolved",
                resolution: resolution,
                arbitrator: (some tx-sender),
                resolved-at: current-block,
                resolution-type: resolution-type
            }
        )
        (map-set document-dispute-summary
            { hash: hash }
            {
                total-disputes: (get total-disputes current-summary),
                active-disputes: (- (get active-disputes current-summary) u1),
                resolved-disputes: (+ (get resolved-disputes current-summary) u1),
                total-evidence-count: (get total-evidence-count current-summary)
            }
        )
        (map-set arbitrators
            { arbitrator: tx-sender }
            {
                is-active: (get is-active arbitrator-info),
                cases-resolved: (+ (get cases-resolved arbitrator-info) u1),
                reputation: (+ (get reputation arbitrator-info) u5)
            }
        )
        (ok true)
    )
)

(define-public (withdraw-dispute
    (hash (string-ascii 64))
    (dispute-id uint))
    (let
        ((dispute-info (unwrap! (map-get? disputes { hash: hash, dispute-id: dispute-id }) ERR-DISPUTE-NOT-FOUND))
         (current-summary (unwrap! (map-get? document-dispute-summary { hash: hash }) ERR-DOCUMENT-NOT-FOUND)))
        (asserts! (is-eq tx-sender (get disputer dispute-info)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status dispute-info) "pending") ERR-DISPUTE-RESOLVED)
        (map-set disputes
            { hash: hash, dispute-id: dispute-id }
            {
                disputer: (get disputer dispute-info),
                reason: (get reason dispute-info),
                initiated-at: (get initiated-at dispute-info),
                status: "withdrawn",
                resolution: "Withdrawn by disputer",
                arbitrator: none,
                resolved-at: stacks-block-height,
                resolution-type: "withdrawn"
            }
        )
        (map-set document-dispute-summary
            { hash: hash }
            {
                total-disputes: (get total-disputes current-summary),
                active-disputes: (- (get active-disputes current-summary) u1),
                resolved-disputes: (+ (get resolved-disputes current-summary) u1),
                total-evidence-count: (get total-evidence-count current-summary)
            }
        )
        (ok true)
    )
)

(define-read-only (get-dispute
    (hash (string-ascii 64))
    (dispute-id uint))
    (ok (map-get? disputes { hash: hash, dispute-id: dispute-id }))
)

(define-read-only (get-dispute-evidence
    (hash (string-ascii 64))
    (dispute-id uint)
    (evidence-id uint))
    (ok (map-get? dispute-evidence { hash: hash, dispute-id: dispute-id, evidence-id: evidence-id }))
)

(define-read-only (get-document-dispute-summary (hash (string-ascii 64)))
    (ok (map-get? document-dispute-summary { hash: hash }))
)

(define-read-only (get-arbitrator-info (arbitrator principal))
    (ok (map-get? arbitrators { arbitrator: arbitrator }))
)

(define-read-only (get-evidence-count
    (hash (string-ascii 64))
    (dispute-id uint))
    (ok (default-to { count: u0 } (map-get? evidence-count { hash: hash, dispute-id: dispute-id })))
)

(define-read-only (has-active-disputes (hash (string-ascii 64)))
    (match (map-get? document-dispute-summary { hash: hash })
        summary-info (ok (> (get active-disputes summary-info) u0))
        (ok false)
    )
)

(define-read-only (get-total-disputes)
    (ok (var-get total-disputes))
)

(define-public (set-max-evidence-per-dispute (max-evidence uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> max-evidence u0) ERR-INVALID-EVIDENCE)
        (var-set max-evidence-per-dispute max-evidence)
        (ok true)
    )
)

(define-read-only (get-max-evidence-per-dispute)
    (ok (var-get max-evidence-per-dispute))
)
