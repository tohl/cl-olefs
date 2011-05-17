(defpackage :ole
  (:use :cl))

(in-package :ole)

(defconstant +unused-sector+ 0)
(defconstant +maxregsect+ #xfffffffa)
(defconstant +difsect+ #xfffffffc)
(defconstant +fatsect+ #xfffffffd)
(defconstant +endofchain+ #xfffffffe)
(defconstant +freesect+ #xffffffff)

(defconstant +maxregsig+ #xfffffffa)
(defconstant +nostream+ #xffffffff)

(deftype ubyte () '(unsigned-byte 8))
(deftype ushort () '(unsigned-byte 16))
(deftype wchar () '(unsigned-byte 16))
(deftype dword () '(unsigned-byte 32))
(deftype ulonglong () '(unsigned-byte 64))
(deftype filetime () '(unsigned-byte 64))
(deftype guid () '(vector ubyte 16))

#+nil
(defconstant clsid-null (make-array 16
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0))

(defun read-value (type stream)
  (if (atom type)
      (ecase type
        (ubyte (read-byte stream))
        (ushort (logior (read-byte stream)
                        (ash (read-byte stream) 8)))
        (wchar (logior (read-byte stream)
                       (ash (read-byte stream) 8)))
        (dword (logior (read-byte stream)
                       (ash (read-byte stream) 8)
                       (ash (read-byte stream) 16)
                       (ash (read-byte stream) 24)))
        (ulonglong (logior (read-byte stream)
                           (ash (read-byte stream) 8)
                           (ash (read-byte stream) 16)
                           (ash (read-byte stream) 24)
                           (ash (read-byte stream) 32)
                           (ash (read-byte stream) 40)
                           (ash (read-byte stream) 48)
                           (ash (read-byte stream) 56)))
        (filetime (read-value 'ulonglong stream))
        (guid (read-value '(ubyte 16) stream)))
      (destructuring-bind (element-type size) type
        (let ((x (make-array size
                             :element-type element-type
                             :initial-element 0)))
          (dotimes (i size x)
            (setf (aref x i) (read-value element-type stream)))))))

(defmacro define-structure (name options &rest slots)
  (declare (ignore options))
  `(progn
     (defstruct (,name (:conc-name ,(intern (format nil "~a." name))))
       ,@(loop
            for (name2 type) in slots
            collect (list name2
                          nil
                          :type (if (atom type)
                                    type
                                    (cons 'vector type)))))
     (defun ,(intern (format nil "READ-~a" name)) (stream)
       (,(intern (format nil "MAKE-~a" name))
         ,@(loop
              for (name2 type) in slots
              appending `(,(intern (symbol-name name2) :keyword)
                           (read-value ',type stream)))))))

(define-structure ole-header ()
  (signature (ubyte 8))
  (clsid guid)
  (minor-version ushort)
  (major-version ushort)
  (byte-order ushort)
  (sector-shift ushort)
  (mini-sector-shift ushort)
  (reserved (ubyte 6))
  (number-of-directory-sectors dword)
  (number-of-fat-sectors dword)
  (first-directory-sector-location dword)
  (transaction-signature-number dword)
  (mini-stream-cutoff-size dword)
  (first-mini-fat-sector-location dword)
  (number-of-mini-fat-sectors dword)
  (first-difat-sector-location dword)
  (number-of-difat-sectors dword))

(define-structure ole-entry ()
  (name (wchar 32))
  (name-length ushort)
  (object-type ubyte)
  (color-flag ubyte)
  (left-sibling-id dword)
  (right-sibling-id dword)
  (child-id dword)
  (clsid guid)
  (state-bits dword)
  (creation-time filetime)
  (modified-time filetime)
  (starting-sector-location dword)
  (stream-size ulonglong))

(defun ole-entry-name-to-string (name length)
  (coerce (mapcar #'code-char (coerce (subseq name 0 (1- (/ length 2))) 'list))
          'string))

(defun print-ole-entry (ole-entry stream)
  (print-unreadable-object (ole-entry stream :type t :identity t)
    (format stream "~s ~a ~a ~sB @~s"
            (ole-entry-name-to-string (ole-entry.name ole-entry)
                                      (ole-entry.name-length ole-entry))
            (ecase (ole-entry.object-type ole-entry)
              (0 "unknown")
              (1 "storage")
              (2 "stream")
              (5 "root"))
            (ecase (ole-entry.color-flag ole-entry)
              (0 "red")
              (1 "black"))
            (ole-entry.stream-size ole-entry)
            (ole-entry.starting-sector-location ole-entry))))

(defun location-position (location)
  (* (1+ location) 512))

(defun seek-sector (location stream)
  (let ((position (location-position location)))
    (assert (file-position stream position))
    location))

(defun check-ole-header (x)
  (assert (equalp #(#xd0 #xcf #x11 #xe0 #xa1 #xb1 #x1a #xe1) (ole-header.signature x)))
  ;;(assert (equalp clsid-null (ole-header.clsid x)))
  (assert (eql #xfffe (ole-header.byte-order x)))
  (assert (equalp #(0 0 0 0 0 0) (ole-header.reserved x)))
  ;; TODO
  (assert (eql 3 (ole-header.major-version x)))
  (assert (eql 512 (ash 1 (ole-header.sector-shift x))))
  (assert (eql 64 (ash 1 (ole-header.mini-sector-shift x))))
  (assert (eql 0 (ole-header.number-of-directory-sectors x)))
  ;;(assert (eql #xfffffffe (first-directory-sector-location x)))
  (assert (eql 0 (ole-header.transaction-signature-number x)))
  (assert (eql 4096 (ole-header.mini-stream-cutoff-size x)))
  ;;(assert (eql #xfffffffe (first-mini-fat-sector-location x)))
  (unless (plusp (ole-header.number-of-difat-sectors x))
    (assert (eql #xfffffffe (ole-header.first-difat-sector-location x)))))

(defstruct (ole-file (:conc-name ole-file.))
  filename stream header difat fat directory-chain directories mfat-chain mfat)

(defun sector-chain (fat location)
  (labels ((rec (x)
             (case x
               ;;(#.+unused-sector+)
               ;;(+maxregsect+)
               (#.+difsect+)
               (#.+fatsect+)
               (#.+endofchain+)
               (#.+freesect+)
               (t
                (assert (and #+nil(< +unused-sector+ x) (<= 0 x +maxregsect+)))
                (cons x (rec (aref fat x)))))))
    (rec location)))

(defun read-values (array type stream &optional (start 0) end)
  (loop
     for i from start below (or end (length array))
     do (setf (aref array i) (read-value type stream))))

(defun read-difat (header stream)
  (let ((x (make-array (+ 109
                          (* #.(/ (- 512 4) 4)
                             (ole-header.number-of-difat-sectors header)))
                       :element-type 'dword)))
    (read-values x 'dword stream 0 109)
    (loop
       with m = #.(1- (/ 512 4))
       for n = (ole-header.first-difat-sector-location header)
       then (read-value 'dword stream)
       for i = 109 then (+ m i)
       until (= +endofchain+ n)
       do (progn
            (seek-sector n stream)
            (read-values x 'dword stream i (+ m i))))
    x))

(defun read-fat (difat stream)
  (let* ((m #.(/ 512 4))
         (n (length difat))
         (x (make-array (* m n) :element-type 'dword)))
    (dotimes (i n x)
      (let ((s (aref difat i)))
        (unless (= +freesect+ s)
          (seek-sector s stream)
          (read-values x 'dword stream (* m i) (* m (1+ i))))))))

(defun read-directories (chain stream)
  (let* ((m #.(/ 512 128))
         (x (make-array (* m (length chain))
                        :element-type '(or null ole-entry)
                        :initial-element nil))
         (i -1))
    (dolist (s chain x)
      (seek-sector s stream)
      (dotimes (j m)
        (setf (aref x (incf i)) (read-ole-entry stream))))))

(defun read-mfat (chain stream)
  (let* ((m #.(/ 512 4))
         (x (make-array (* m (length chain)) :element-type 'dword))
         (i -1))
    (dolist (s chain x)
      (seek-sector s stream)
      ;;TODO block read (read-values x 'dword stream (* m i) (* m (1+ i)))
      (dotimes (j m)
        (setf (aref x (incf i)) (read-value 'dword stream))))))

(defun traverse-directories (ole-file callback)
  (let ((d (ole-file.directories ole-file)))
    (labels ((rec (n level)
               (let ((e (aref d n)))
                 (unless (zerop (ole-entry.object-type e))
                   (funcall callback e n level)
                   (let ((id (ole-entry.left-sibling-id e)))
                     (when (<= id +maxregsig+)
                       (rec id level)))
                   (let ((id (ole-entry.child-id e)))
                     (when (<= id +maxregsig+)
                       (rec id (1+ level))))
                   (let ((id (ole-entry.right-sibling-id e)))
                     (when (<= id +maxregsig+)
                       (rec id level)))))))
      (rec 0 0))))

(defun call-with-ole-file (filename fn)
  (with-open-file (stream filename :element-type '(unsigned-byte 8))
    (let* ((header (read-ole-header stream))
           (difat (read-difat header stream))
           (fat (read-fat difat stream))
           (directory-chain (sector-chain
                             fat
                             (ole-header.first-directory-sector-location header)))
           (directories (read-directories directory-chain stream))
           (mfat-chain (sector-chain
                        fat
                        (ole-header.first-mini-fat-sector-location header)))
           (mfat (read-mfat mfat-chain stream))
           (ole-file (make-ole-file
                      :filename filename
                      :stream stream
                      :header header
                      :difat difat
                      :fat fat
                      :directory-chain directory-chain
                      :directories directories
                      :mfat-chain mfat-chain
                      :mfat mfat)))
      (describe ole-file)
      (check-ole-header (ole-file.header ole-file))
      (describe header)
      (terpri)
      (traverse-directories ole-file
                            (lambda (entry id level)
                              (declare (ignore id))
                              (dotimes (i level)
                                (write-string "   "))
                              (print-ole-entry entry *standard-output*)
                              (terpri)))
      ;; TODO small block chain for root entry
      (funcall fn ole-file))))

(defmacro with-ole-file ((ole-file filename) &body body)
  `(call-with-ole-file ,filename (lambda (,ole-file) ,@body)))

(defun save-chain (ole-stream chain filename length)
  (with-open-file (s filename
                     :direction :output
                     :if-does-not-exist :create
                     :if-exists :supersede
                     :element-type '(unsigned-byte 8))
    (let ((buf (make-array 512 :element-type '(unsigned-byte 8))))
      (dolist (x chain)
        (seek-sector x ole-stream)
        (let ((n (read-sequence buf ole-stream)))
          (decf length n)
          (write-sequence buf s :end (if (plusp length) n (+ length 512))))))))

(defun save-entry-stream (ole-file entry filename)
  (if (<= (ole-entry.stream-size entry)
          (ole-header.mini-stream-cutoff-size (ole-file.header ole-file)))
      (save-chain (ole-file.stream ole-file) ;; TODO mini stream, mfat?
                  (sector-chain (ole-file.fat ole-file) ;; mfat?
                                (ole-entry.starting-sector-location
                                 (aref (ole-file.directories ole-file) 0)))
                  filename
                  (ole-entry.stream-size entry))
      (save-chain (ole-file.stream ole-file)
                  (sector-chain (ole-file.fat ole-file)
                                (ole-entry.starting-sector-location entry))
                  filename
                  (ole-entry.stream-size entry))))

(defun extract-ole-file (filename)
  (with-ole-file (ole-file filename)
    (traverse-directories
     ole-file
     (lambda (entry id level)
       (declare (ignore id level))
       (case (ole-entry.object-type entry)
         ;;(1 "storage")
         (2 ;; stream
          (save-entry-stream ole-file
                             entry
                             (format nil "/tmp/~a"
                                     (ole-entry-name-to-string
                                      (ole-entry.name entry)
                                      (ole-entry.name-length entry))))))))))


(defclass ole-entry-stream (trivial-gray-streams:fundamental-binary-input-stream)
  ((ole-file :initarg :ole-file)
   (ole-entry :initarg :ole-entry)
   (offset :initform 0)
   (chain)
   (mchain)
   (sector :initform nil)
   (buffer :initform (make-array 512 :element-type '(unsigned-byte 8)))
   (size)))

(defmethod initialize-instance :after ((instance ole-entry-stream) &rest initargs)
  (declare (ignore initargs))
  (with-slots (ole-file ole-entry chain mchain buffer size) instance
    (let ((mini (< (ole-entry.stream-size ole-entry)
                   (ole-header.mini-stream-cutoff-size (ole-file.header ole-file)))))
      (setq chain (coerce
                   (sector-chain
                    (ole-file.fat ole-file)
                    (ole-entry.starting-sector-location
                     (if mini
                         (aref (ole-file.directories ole-file) 0)
                         ole-entry)))
                   'vector)
            mchain (when mini
                     (coerce
                      (sector-chain
                       (ole-file.mfat ole-file)
                       (ole-entry.starting-sector-location ole-entry))
                      'vector))
            size (ole-entry.stream-size ole-entry)))))

(defmethod trivial-gray-streams::stream-element-type ((stream ole-entry-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-read-byte ((stream ole-entry-stream))
  (with-slots (ole-file ole-entry offset chain mchain sector buffer size) stream
    (assert (not (minusp offset)))
    (if (< offset size)
        (multiple-value-bind (q r) (floor offset 512)
          (unless (eql sector q)
            (let ((ole-stream (ole-file.stream ole-file)))
              (seek-sector (aref chain q) ole-stream)
              (let ((n (read-sequence buffer ole-stream)))
                (assert (eql 512 n))))
            (setq sector q))
          (prog1 (aref buffer r)
            (incf offset)))
        :eof)))

(defun call-with-ole-entry-stream (stream fn)
  (with-open-stream (x stream)
    (funcall fn x)))

(defmacro with-ole-entry-stream ((var ole-file ole-entry) &body body)
  `(call-with-ole-entry-stream
    (make-instance 'ole-entry-stream :ole-file ,ole-file :ole-entry ,ole-entry)
    (lambda (,var) ,@body)))


(define-structure OfficeArtRecordHeader ()
  (recVer ushort :always 0)
  (recInstance ushort :member '(#x46A #x46B #x6E2 #x6E3))
  (recType ushort :always #xF01D)
  (recLen ushort))

(define-structure OfficeArtBlipJPEG ()
  ;;(rh OfficeArtRecordHeader)
  (rgbUid1 guid)
  (rgbUid2 guid ;;:optional '(when (member recInstance '(#x46B #x6E3)))
           )
  (tag ubyte)
  #+nil(BLIBFileData))

(defun extract-ole-file2 (filename)
  (with-ole-file (ole-file filename)
    (traverse-directories
     ole-file
     (lambda (entry id level)
       (declare (ignore id level))
       (case (ole-entry.object-type entry)
         ;;(1 "storage")
         (2 ;; stream
          (let ((entry-name (ole-entry-name-to-string
                             (ole-entry.name entry)
                             (ole-entry.name-length entry))))
            (with-ole-entry-stream (in ole-file entry)
              (with-open-file (out (format nil "/tmp/a/~a" entry-name)
                                   :direction :output
                                   :if-does-not-exist :create
                                   :if-exists :supersede
                                   :element-type '(unsigned-byte 8))
                (alexandria:copy-stream in out)))
            (when (equal "Pictures" entry-name)
              (with-ole-entry-stream (in ole-file entry)
                (print (read-OfficeArtRecordHeader in))
                (print (read-value 'guid in))
                (read-value 'ubyte in)
                (with-open-file (out "/tmp/a/a.jpeg"
                                     :direction :output
                                     :if-does-not-exist :create
                                     :if-exists :supersede
                                     :element-type '(unsigned-byte 8))
                  (alexandria:copy-stream in out)))))))))))

