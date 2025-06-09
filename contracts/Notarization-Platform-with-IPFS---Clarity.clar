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
