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