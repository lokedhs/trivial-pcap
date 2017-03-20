(cl:eval-when (:load-toplevel :execute)
  (asdf:operate 'asdf:load-op 'cffi-grovel))

(defsystem :pcap
  :name "pcap"
  :author "Elias Mårtenson <lokedhs@gmail.com>"
  :license "BSD"
  :description "libpcap interface to Common Lisp"
  :depends-on (:cffi
               :cffi-grovel)
  :components ((:module src
                        :serial t
                        :components ((:file "package")
                                     (cffi-grovel:grovel-file "grovel")
                                     (:file "functions")
                                     (:file "trivial-pcap")))))
