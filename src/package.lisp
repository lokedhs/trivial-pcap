(defpackage :pcap
  (:use :cl)
  (:documentation "libpcap interface to Common Lisp")
  (:export #:open-offline
           #:open-offline-with-tstamp-precision
           #:close-pcap
           #:with-offline
           #:stats
           #:compile-pcap
           #:setfilter
           #:pcap-stats
           #:compiled-program
           #:next-pcap
           #:packet
           #:pcap
           #:pcap-error
           #:pcap-error/message
           #:snapshot
           #:is-swapped
           #:major-version
           #:minor-version
           #:with-compiled-program
           #:offline-filter
           #:packet-free))
