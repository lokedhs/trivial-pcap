(in-package :pcap)

(include "pcap.h")

(constant (+pcap-errbuf-size+ "PCAP_ERRBUF_SIZE"))
(constant (+pcap-tstamp-precision-micro+ "PCAP_TSTAMP_PRECISION_MICRO"))
(constant (+pcap-tstamp-precision-nano+ "PCAP_TSTAMP_PRECISION_NANO"))
(constant (+pcap-netmask-unknown+ "PCAP_NETMASK_UNKNOWN"))
(constant (+pcap-error-not-activated+ "PCAP_ERROR_NOT_ACTIVATED"))

(ctype u-int "u_int")
(ctype u-short "u_short")
(ctype u-char "u_char")
(ctype bpf-u-int32 "bpf_u_int32")
(ctype time-t "time_t")

(cstruct timeval "struct timeval"
         (tv-sec "tv_sec" :type time-t)
         (tv-usec "tv_usec" :type :long))

(cstruct pcap-pkthdr "struct pcap_pkthdr"
         (ts "ts" :type (:struct timeval))
         (caplen "caplen" :type bpf-u-int32)
         (len "len" :type bpf-u-int32))

(cstruct pcap-stat "struct pcap_stat"
         (ps-recv "ps_recv" :type u-int)
         (ps-drop "ps_drop" :type u-int)
         (ps-ifdrop "ps_ifdrop" :type u-int))

(cstruct bpf-insn "struct bpf_insn"
         (code "code" :type u-short)
         (jt "jt" :type u-char)
         (jf "jf" :type u-char)
         (k "k" :type bpf-u-int32))

(cstruct bpf-program "struct bpf_program"
         (bf-len "bf_len" :type u-int)
         (bf-insns "bf_insns" :type (:pointer (:struct bpf-insn))))
