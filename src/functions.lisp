(in-package :pcap)

(cffi:define-foreign-library libpcap
  (:unix "libpcap.so"))

(cffi:use-foreign-library libpcap)

(cffi:defcfun ("pcap_geterr" pcap-geterr-internal) :string
  (pcap :pointer))

(cffi:defcfun ("pcap_open_offline" pcap-open-offline-internal) :pointer
  (fname :string)
  (errbuf (:pointer :char)))

(cffi:defcfun ("pcap_open_offline_with_tstamp_precision" pcap-open-offline-with-tstamp-precision-internal) :pointer
  (fname :string)
  (precision u-int)
  (errbuf (:pointer :char)))

(cffi:defcfun ("pcap_close" pcap-close-internal) :void
  (pcap :pointer))

(cffi:defcfun ("pcap_next" pcap-next-internal) (:pointer u-char)
  (pcap :pointer)
  (header (:pointer (:struct pcap-pkthdr))))

(cffi:defcfun ("pcap_next_ex" pcap-next-ex-internal) :int
  (pcap :pointer)
  (pkt-header (:pointer (:pointer (:struct pcap-pkthdr))))
  (pkt-data (:pointer (:pointer u-char))))

(cffi:defcfun ("pcap_stats" pcap-stats-internal) :int
  (pcap :pointer)
  (ps (:pointer (:struct pcap-stat))))

(cffi:defcfun ("pcap_compile" pcap-compile-internal) :int
  (pcap :pointer)
  (bpf-program (:pointer (:struct bpf-program)))
  (str :string)
  (opt :int)
  (netmask bpf-u-int32))

(cffi:defcfun ("pcap_freecode" pcap-freecode-internal) :void
  (program (:pointer (:struct bpf-program))))

(cffi:defcfun ("pcap_offline_filter" pcap-offline-filter-internal) :int
  (program (:pointer (:struct bpf-program)))
  (h (:pointer (:struct pcap-pkthdr)))
  (pkt (:pointer u-char)))

(cffi:defcfun ("pcap_setfilter" pcap-setfilter-internal) :int
  (pcap :pointer)
  (bpf-program (:pointer (:struct bpf-program))))

(cffi:defcfun ("pcap_snapshot" pcap-snapshot-internal) :int
  (pcap :pointer))

(cffi:defcfun ("pcap_is_swapped" pcap-is-swapped-internal) :int
  (pcap :pointer))

(cffi:defcfun ("pcap_major_version" pcap-major-version-internal) :int
  (pcap :pointer))

(cffi:defcfun ("pcap_minor_version" pcap-minor-version-internal) :int
  (pcap :pointer))
