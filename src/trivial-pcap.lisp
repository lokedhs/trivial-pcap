(in-package :pcap)

(define-condition pcap-error (error)
  ((message :type string
            :initarg :message
            :reader pcap-error/message))
  (:report (lambda (condition out)
             (format out "pcap error: ~a" (pcap-error/message condition)))))

(defun not-activated-error ()
  (error 'pcap-error "Capture handle is not activated"))

(defclass pcap ()
  ((ptr :initarg :ptr
        :reader pcap/ptr)))

(defmacro with-pcap-load-error-handler ((errbuf) &body body)
  (check-type errbuf symbol)
  (let ((res-sym (gensym "RESULT"))
        (errbuf-sym (gensym "ERRBUF")))
    `(cffi:with-foreign-object (,errbuf-sym :char +PCAP-ERRBUF-SIZE+)
       (let ((,res-sym (let ((,errbuf ,errbuf-sym))
                         ,@body)))
         (when (cffi:null-pointer-p ,res-sym)
           (error 'pcap-error :message (cffi:foreign-string-to-lisp ,errbuf-sym)))
         ,res-sym))))

(defmacro with-pcap-error-handler (pcap form &optional deallocate)
  (alexandria:with-gensyms (pcap-sym res)
    `(let ((,pcap-sym ,pcap)
           (,res ,form))
       (when (minusp ,res)
         ,@(if deallocate
               (list deallocate))
         (error 'pcap-error :message (pcap-geterr-internal (pcap/ptr ,pcap-sym))))
       ,res)))

(defun major-version (pcap)
  (check-type pcap pcap)
  (pcap-major-version-internal (pcap/ptr pcap)))

(defun minor-version (pcap)
  (check-type pcap pcap)
  (pcap-minor-version-internal (pcap/ptr pcap)))

(defun open-offline (fname)
  (make-instance 'pcap :ptr (with-pcap-load-error-handler (errbuf)
                              (pcap-open-offline-internal fname errbuf))))

(defun open-offline-with-tstamp-precision (fname precision)
  (let ((p (ecase precision
             (:micro +PCAP-TSTAMP-PRECISION-MICRO+)
             (:nano +PCAP-TSTAMP-PRECISION-NANO+))))
    (make-instance 'pcap
                   :ptr (with-pcap-load-error-handler (errbuf)
                          (pcap-open-offline-with-tstamp-precision-internal fname p errbuf)))))

(defun close-pcap (pcap)
  (check-type pcap pcap)
  (pcap-close-internal (pcap/ptr pcap)))

(defmacro with-offline ((pcap fname) &body body)
  (alexandria:with-gensyms (pcap-sym)
    `(let ((,pcap-sym (open-offline ,fname)))
       (unwind-protect
            (let ((,pcap ,pcap-sym))
              ,@body)
         (close-pcap ,pcap-sym)))))

(defclass packet ()
  ((header    :type t
              :initarg :header
              :reader packet/header)
   (content   :type t
              :initarg :content
              :reader packet/content)
   (need-free :type t
              :initarg :need-free
              :reader packet/need-free)
   (active    :type t
              :initform t
              :accessor packet/active)))

(defgeneric packet/ts (packet)
  (:method ((packet packet))
    (make-timestamp (cffi:foreign-slot-value (packet/header packet) '(:struct pcap-pkthdr) 'ts))))

(defgeneric packet/length (packet)
  (:method ((packet packet))
    (cffi:foreign-slot-value (packet/header packet) '(:struct pcap-pkthdr) 'len)))

(defgeneric packet/caplen (packet)
  (:method ((packet packet))
    (cffi:foreign-slot-value (packet/header packet) '(:struct pcap-pkthdr) 'caplen)))

(defun make-timestamp (timestamp)
  (let ((sec (getf timestamp 'tv-sec))
        (usec (getf timestamp 'tv-usec)))
    (+ sec (/ usec 1000000))))

(defun alloc-and-copy (ptr size)
  (let ((buf (cffi:foreign-alloc :char :count size)))
    (loop
      for i from 0 below size
      do (setf (cffi:mem-aref buf :char i) (cffi:mem-aref ptr :char i)))
    buf))

(defun next-pcap (pcap &key (copy-packet nil))
  (check-type pcap pcap)
  (cffi:with-foreign-objects ((header-ref '(:pointer (:struct pcap-pkthdr)))
                              (content-ref '(:pointer u-char)))
    (let ((res (pcap-next-ex-internal (pcap/ptr pcap) header-ref content-ref)))
      (ecase res
        (0 nil)
        (1 (labels ((maybe-copy (ptr size)
                      (if copy-packet
                          (alloc-and-copy ptr size)
                          ptr)))
             (let* ((header (cffi:mem-ref header-ref '(:pointer (:struct pcap-pkthdr)))))
               (make-instance 'packet
                              :header (maybe-copy header (cffi:foreign-type-size '(:struct pcap-pkthdr)))
                              :content (maybe-copy (cffi:mem-ref content-ref '(:pointer u-char))
                                                   (cffi:foreign-slot-value header '(:struct pcap-pkthdr) 'len))
                              :need-free copy-packet))))
        (-1 (error 'pcap-error :message (pcap-geterr-internal (pcap/ptr pcap))))
        (-2 (error 'pcap-error :message "No matching packets found"))))))

(defun packet-free (packet)
  (check-type packet packet)
  (unless (packet/need-free packet)
    (error "Packet refers to internal pcap memory. It should not be freed."))
  (unless (packet/active packet)
    (error "This packet is no longer active."))
  (cffi:foreign-free (packet/header packet))
  (cffi:foreign-free (packet/content packet))
  (setf (packet/active packet) nil))

(defclass pcap-stats ()
  ((recv   :type integer
           :initarg :recv
           :reader pcap-stats/recv)
   (drop   :type integer
           :initarg :drop
           :reader pcap-stats/drop)
   (ifdrop :type integer
           :initarg :ifdrop
           :reader pcap-stats/ifdrop)))

(defun stats (pcap)
  (check-type pcap pcap)
  (cffi:with-foreign-object (ps '(:struct pcap-stat))
    (with-pcap-error-handler pcap (pcap-stats-internal (pcap/ptr pcap) ps))
    (make-instance 'pcap-stats
                   :recv (cffi:foreign-slot-value ps '(:struct pcap-stat) 'ps-recv)
                   :drop (cffi:foreign-slot-value ps '(:struct pcap-stat) 'ps-drop)
                   :ifdrop (cffi:foreign-slot-value ps '(:struct pcap-stat) 'ps-ifdrop))))

(defclass compiled-program ()
  ((ptr :initarg :ptr
        :reader compiled-program/ptr)))

(defun compile-pcap (pcap program &key opt (netmask :unknown))
  (check-type pcap pcap)
  (check-type program string)
  (check-type netmask (or (eql :unknown) (integer 0)))
  (let ((prog-return (cffi:foreign-alloc '(:struct bpf-program))))
    (with-pcap-error-handler pcap
      (pcap-compile-internal (pcap/ptr pcap) prog-return program (if opt 1 0)
                             (if (eq netmask :unknown)
                                 +PCAP-NETMASK-UNKNOWN+
                                 netmask))
      ;; If the compilation fails, free the memory
      (cffi:foreign-free prog-return))
    (make-instance 'compiled-program :ptr prog-return)))

(defun freecode (program)
  (check-type program compiled-program)
  (pcap-freecode-internal (compiled-program/ptr program)))

(defmacro with-compiled-program ((symbol pcap program &key opt (netmask :unknown)) &body body)
  (alexandria:with-gensyms (program-sym)
    (alexandria:once-only (pcap program opt netmask)
      `(let ((,program-sym (compile-pcap ,pcap ,program :opt ,opt :netmask ,netmask)))
         (unwind-protect
              (let ((,symbol ,program-sym))
                ,@body)
           (freecode ,program-sym))))))

(defun offline-filter (program packet)
  (check-type program compiled-program)
  (check-type packet packet)
  (let ((res (pcap-offline-filter-internal (compiled-program/ptr program)
                                           (packet/header packet)
                                           (packet/content packet))))
    (if (zerop res)
        nil
        t)))

(defun setfilter (pcap filter)
  (check-type pcap pcap)
  (check-type filter compiled-program)
  (with-pcap-error-handler pcap (pcap-setfilter-internal (pcap/ptr pcap) (compiled-program/ptr filter)))
  nil)

(defun snapshot (pcap)
  (check-type pcap pcap)
  (let ((res (pcap-snapshot-internal (pcap/ptr pcap))))
    (if (eql res +PCAP-ERROR-NOT-ACTIVATED+)
        (not-activated-error)
        res)))

(defun is-swapped (pcap)
  (check-type pcap pcap)
  (let ((res (pcap-is-swapped-internal (pcap/ptr pcap))))
    (cond ((eql res 0) nil)
          ((eql res 1) t)
          ((eql res +PCAP-ERROR-NOT-ACTIVATED+)
           (not-activated-error))
          (t
           (error "Unexpected return value from pcap-is-swapped-internal: ~s" res)))))
