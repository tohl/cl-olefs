;;; Copyright (C) 2011, 2012, 2013, 2014 Tomas Hlavaty <tom@logand.com>
;;;
;;; Permission is hereby granted, free of charge, to any person
;;; obtaining a copy of this software and associated documentation
;;; files (the "Software"), to deal in the Software without
;;; restriction, including without limitation the rights to use, copy,
;;; modify, merge, publish, distribute, sublicense, and/or sell copies
;;; of the Software, and to permit persons to whom the Software is
;;; furnished to do so, subject to the following conditions:
;;;
;;; The above copyright notice and this permission notice shall be
;;; included in all copies or substantial portions of the Software.
;;;
;;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
;;; HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
;;; WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;;; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
;;; DEALINGS IN THE SOFTWARE.

(in-package :olefs)

(defun double-float-from-bits (high low)
  (declare (optimize (speed 3) (debug 0))
           (type (unsigned-byte 32) high low))
  #+ccl
  (ccl::double-float-from-bits high low)
  #+sbcl
  (sb-kernel:make-double-float (sb-c::mask-signed-field 32 high) low)
  #-(or ccl sbcl)
  (let ((bignum 0))
    (declare (type (unsigned-byte 64) bignum))
    (setf (ldb (byte 32  0) bignum) low
          (ldb (byte 32 32) bignum) high)
    (ieee-floats:decode-float64 bignum)))

(defmacro with-stream ((var stream) &body body)
  `(let ((,var ,stream))
     (unwind-protect (progn ,@body)
       (funcall ,var 'close))))

(defun stream-position (stream &optional newpos)
  (if (functionp stream)
      (funcall stream 'stream-position newpos)
      (if newpos
          (file-position stream newpos)
          (file-position stream))))

(defun physical-stream-position (stream)
  (if (functionp stream)
      (funcall stream 'physical-stream-position)
      (file-position stream)))

(defun read-octet (stream)
  (if (functionp stream)
      (funcall stream 'read-octet)
      (read-byte stream)))

(defun copy-stream (in out)
  (handler-case (loop (write-byte (read-octet in) out))
    (end-of-file ())))

(defun copy-file (in out)
  (with-open-file (i in :element-type '(unsigned-byte 8))
    (with-open-file (o out
                       :element-type '(unsigned-byte 8)
                       :direction :output
                       :if-exists :error
                       :if-does-not-exist :create)
      (loop
         with buf = (make-array 4096 :element-type '(unsigned-byte 8))
         with n = nil
         while (plusp (setq n (read-sequence buf i)))
         do (write-sequence buf o :end n)))))

(defun shorter-stream (stream size)
  (let ((offset 0)
        self)
    (setq self
          (lambda (msg)
            (assert stream)
            (ecase msg
              (close (setq stream nil))
              (stream-position offset)
              (physical-stream-position (physical-stream-position stream))
              (read-octet
               (unless (< offset size)
                 (error 'end-of-file :stream self))
               (incf offset)
               (read-octet stream)))))))

(defun vector-stream (vector physical-stream-position)
  (let ((offset 0)
        (size (length vector))
        self)
    (setq self
          (lambda (msg)
            (assert vector)
            (ecase msg
              (close (setq vector nil))
              (stream-position offset)
              (physical-stream-position (+ offset physical-stream-position))
              (read-octet
               (unless (< offset size)
                 (error 'end-of-file :stream self))
               (prog1 (aref vector offset)
                 (incf offset))))))))

;;; MS-CFB Compound File Binary File Format

(defconstant +unused-sector+ 0)
(defconstant +maxregsect+ #xfffffffa)
(defconstant +difsect+ #xfffffffc)
(defconstant +fatsect+ #xfffffffd)
(defconstant +endofchain+ #xfffffffe)
(defconstant +freesect+ #xffffffff)

(defconstant +maxregsig+ #xfffffffa)
(defconstant +nostream+ #xffffffff)

#+nil
(defconstant clsid-null (make-array 16
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0))

(defun read-ushort (stream)
  (logior (read-octet stream)
          (ash (read-octet stream) 8)))

(defun read-dword (stream)
  (logior (read-octet stream)
          (ash (read-octet stream) 8)
          (ash (read-octet stream) 16)
          (ash (read-octet stream) 24)))

(defun read-ulonglong (stream)
  (logior (read-octet stream)
          (ash (read-octet stream) 8)
          (ash (read-octet stream) 16)
          (ash (read-octet stream) 24)
          (ash (read-octet stream) 32)
          (ash (read-octet stream) 40)
          (ash (read-octet stream) 48)
          (ash (read-octet stream) 56)))

(defun read-achar (stream)
  (read-octet stream))

(defun read-wchar (stream)
  (read-ushort stream))

(defun read-filetime (stream)
  (read-ulonglong stream))

(defun read-octets (stream n)
  (let ((x (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
    (if (functionp stream)
        (let ((i 0))
          (handler-case (do ()
                            ((<= n i))
                          (setf (aref x i) (read-octet stream))
                          (incf i))
            (end-of-file () i)))
        (read-sequence x stream))
    x))

(defun read-guid (stream)
  (read-octets stream 16))

(defun read-vector (stream n element-type reader)
  (let ((x (make-array n :element-type element-type :initial-element 0)))
    (dotimes (i n x)
      (setf (aref x i) (funcall reader stream)))))

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

(defun string-from-achars (achars &optional length) ;; TODO encoding?
  (let* ((n (or length (length achars)))
         (s (make-string n)))
    (dotimes (i n s)
      (let ((c (aref achars i)))
        (assert (plusp c))
        (setf (aref s i) (code-char c))))))

(defun string-from-wchars (wchars &optional length) ;; TODO encoding?
  (let* ((n (or length (length wchars)))
         (s (make-string n)))
    (dotimes (i n s)
      (let ((c (aref wchars i)))
        (assert (plusp c))
        (setf (aref s i) (code-char c))))))

(defun string-from-octets (octets fHighByte &optional nbytes) ;; TODO encoding?
  (if fHighByte
      (multiple-value-bind (n m) (floor (or nbytes (length octets)) 2)
        (assert (zerop m))
        (let ((s (make-string n)))
          (dotimes (i n s)
            (let ((c (let ((2*i (ash i 1)))
                       (+ (aref octets 2*i)
                          (ash (aref octets (1+ 2*i)) 8)))))
              (assert (plusp c))
              (setf (aref s i) (code-char c))))))
      (string-from-achars octets nbytes)))

(defun ole-entry-name-to-string (octets n)
  (multiple-value-bind (n m) (floor n 2)
    (assert (zerop m))
    (string-from-achars octets (1- n)))) ;; minus #\null

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
    (assert (stream-position stream position))
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

(defun sector-chain (fat location)
  (labels ((rec (x)
             (unless (member x (list +difsect+ +fatsect+ +endofchain+ +freesect+))
               (assert (and #+nil(< +unused-sector+ x) (<= 0 x +maxregsect+)))
               (cons x (rec (aref fat x))))))
    (rec location)))

(defun read-values (array reader stream &optional (start 0) end)
  (loop
     for i from start below (or end (length array))
     do (setf (aref array i) (funcall reader stream))))

(defun read-difat (header stream)
  (let ((x (make-array (+ 109
                          (* #.(/ (- 512 4) 4)
                             (ole-header.number-of-difat-sectors header)))
                       :element-type 'dword)))
    (read-values x 'read-dword stream 0 109)
    (loop
       with m = #.(1- (/ 512 4))
       for n = (ole-header.first-difat-sector-location header)
       then (read-dword stream)
       for i = 109 then (+ m i)
       until (= +endofchain+ n)
       do (progn
            (seek-sector n stream)
            (read-values x 'read-dword stream i (+ m i))))
    x))

(defun read-fat (difat stream)
  (let* ((m #.(/ 512 4))
         (n (length difat))
         (x (make-array (* m n) :element-type 'dword)))
    (dotimes (i n x)
      (let ((s (aref difat i)))
        (unless (= +freesect+ s)
          (seek-sector s stream)
          (read-values x 'read-dword stream (* m i) (* m (1+ i))))))))

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
      ;;TODO block read (read-values x 'read-dword stream (* m i) (* m (1+ i)))
      (dotimes (j m)
        (setf (aref x (incf i)) (read-dword stream))))))

(defun %ole-entry-stream (header fat directories mfat stream ole-entry)
  (let* ((offset 0)
         (mini (< (ole-entry.stream-size ole-entry)
                  (ole-header.mini-stream-cutoff-size header)))
         (chain (let ((x (sector-chain
                          fat
                          (ole-entry.starting-sector-location
                           (if mini
                               (aref directories 0)
                               ole-entry)))))
                  (when x
                    (coerce x 'vector))))
         (mchain (when mini
                   (let ((x (sector-chain
                             mfat
                             (ole-entry.starting-sector-location ole-entry))))
                     (when x
                       (coerce x 'vector)))))
         sector
         (buffer (make-array 512 :element-type '(unsigned-byte 8)))
         (size (ole-entry.stream-size ole-entry))
         self)
    (setq self
          (lambda (msg &rest args)
            (assert stream)
            (flet ((next-octet (consumep)
                     ;; (values <current-byte> <position-of-current-byte>)
                     ;; Advance the stream by a byte if CONSUMEP is true, except at eof.
                     (assert (not (minusp offset)))
                     (unless (< offset size)
                       (error 'end-of-file :stream self))
                     (flet ((pick (q i)
                              (unless (eql sector q)
                                (seek-sector (aref chain q) stream)
                                (let ((n (read-sequence buffer stream)))
                                  (assert (eql 512 n)))
                                (setq sector q))
                              (multiple-value-prog1
                                  (values (aref buffer i)
                                          (+ i (location-position (aref chain sector))))
                                (when consumep
                                  (incf offset)))))
                       (if mchain
                           (multiple-value-bind (mq mr) (floor offset 64)
                             (multiple-value-bind (q r) (floor (aref mchain mq) (/ 512 64))
                               (pick q (+ (* r 64) mr))))
                           (multiple-value-bind (q r) (floor offset 512)
                             (pick q r))))))
              (ecase msg
                (close (setq stream nil))
                (stream-position
                 (destructuring-bind (&optional newpos) args
                   (if newpos
                       (setf offset newpos
                             sector nil)
                       offset)))
                (physical-stream-position (nth-value 1 (next-octet nil)))
                (read-octet (values (next-octet t)))))))))

(defun ole-entry-stream (ole-file entry)
  (funcall ole-file 'ole-entry-stream entry))

(defun ole-directory-stream (ole-file)
  (funcall ole-file 'ole-directory-stream))

(defun find-ole-entry (ole-file &key name type)
  (loop
     with s = (ole-directory-stream ole-file)
     with e = nil
     while (setq e (funcall s))
     do (when (and (or (not type)
                       (let ((x (ole-entry.object-type e)))
                         (if (atom type)
                             (eql x type)
                             (member x type))))
                   (or (not name)
                       (let ((x (ole-entry-name-to-string
                                 (ole-entry.name e)
                                 (ole-entry.name-length e))))
                         (if (atom name)
                             (equal x name)
                             (member x name :test #'equal)))))
          (return-from find-ole-entry e))))

(defun %ole-directory-stream (directories)
  (let ((pending (list (cons 0 0))))
    (lambda ()
      (block done
        (loop
           (if pending
               (destructuring-bind (n &rest level) (pop pending)
                 (let ((e (aref directories n)))
                   (unless (zerop (ole-entry.object-type e))
                     (let ((id (ole-entry.right-sibling-id e)))
                       (when (<= id +maxregsig+)
                         (push (cons id level) pending)))
                     (let ((id (ole-entry.child-id e)))
                       (when (<= id +maxregsig+)
                         (push (cons id (1+ level)) pending)))
                     (let ((id (ole-entry.left-sibling-id e)))
                       (when (<= id +maxregsig+)
                         (push (cons id level) pending)))
                     (return-from done (values e n level)))))
               (return-from done)))))))

(defun ole-file-stream (filename)
  (let* ((stream (open filename :element-type '(unsigned-byte 8)))
         (header (read-ole-header stream))
         (difat (read-difat header stream))
         (fat (read-fat difat stream))
         (directory-chain (sector-chain
                           fat
                           (ole-header.first-directory-sector-location header)))
         (directories (read-directories directory-chain stream))
         (mfat-chain (sector-chain
                      fat
                      (ole-header.first-mini-fat-sector-location header)))
         (mfat (read-mfat mfat-chain stream)))
    (check-ole-header header)
    ;;(describe header)
    ;;(terpri)
    (lambda (msg &rest args)
      (assert stream)
      (ecase msg
        (close
         (close stream)
         (setq stream nil))
        (ole-entry-stream
         (destructuring-bind (entry) args
           (%ole-entry-stream header fat directories mfat stream entry)))
        (ole-directory-stream (%ole-directory-stream directories))))))

(defun extract-pictures (ole-file dir html)
  (walk-RecordHeader-tree
   ole-file
   (find-ole-entry ole-file :name "Pictures" :type 2)
   (lambda (in level i h start end parents)
     (declare (ignore level start end parents))
     (multiple-value-bind (blip kind)
         (read-record-body
          in
          h
          (lambda (blip in)
            (with-open-file (out (format nil "~a/~d.~a"
                                         dir
                                         i
                                         (blip-ext blip))
                                 :direction :output
                                 :if-does-not-exist :create
                                 :if-exists :supersede
                                 :element-type '(unsigned-byte 8))
              (copy-stream in out))))
       (declare (ignore blip))
       (when html
         (format html "<p><img src=\"~d.~(~a~)\">~%" i kind))))))

(defun extract-ole-file (filename &optional (dir "/tmp")) ;; TODO extract audio files
  (with-stream (ole-file (ole-file-stream filename))
    (with-open-file (html (format nil "~a/index.html" dir)
                          :direction :output
                          :if-does-not-exist :create
                          :if-exists :supersede
                          :element-type 'character)
      (extract-pictures ole-file dir html))))

;;; MS-PPT PowerPoint (.ppt) Binary File Format

(define-structure RecordHeader ()
  (%dummy1 ubyte)
  (%dummy2 ubyte)
  (recVer t :compute (logand #x0f %dummy1))
  (recInstance t :compute (logior (ash %dummy2 4) (ash %dummy1 -4)))
  (recType ushort)
  (recLen dword))

(define-structure CurrentUserAtom ()
  (size dword :always #x14)
  (headerToken dword)
  (offsetToCurrentEdit dword)
  (lenUserName ushort)
  (docFileVersion ushort)
  (majorVersion ubyte)
  (minorVersion ubyte)
  (unused ushort)
  (ansiUserName (achar lenUserName))
  (relVersion dword)
  (unicodeUserName (wchar lenUserName)))

;;; MS-ODRAW Office Drawing Binary File Format

(define-structure POINT ()
  (x dword)
  (y dword))

(define-structure RECT ()
  (left dword)
  (top dword)
  (right dword)
  (bottom dword))

(define-structure OfficeArtMetafileHeader ()
  (cbSize dword)
  (rcBounds RECT)
  (ptSize POINT)
  (cbSave dword)
  (compression ubyte :member '(#x00 #xfe))
  (filter ubyte :always #xfe))

(define-structure PersistDirectoryEntry ()
  (%dummy dword)
  (persistId t :compute (logand #xfffff %dummy))
  (cPersist t :compute (ash %dummy -20))
  (rgPersistOffset (dword cPersist)))

(defstruct blip header ext guid guid2 metafileHeader)

(defstruct PersistDirectoryAtom header entries)

(defun read-record-body (stream RecordHeader &optional fn) ;; TODO move up?!
  (let ((x RecordHeader #+nil(read-RecordHeader stream)))
    (with-slots (recVer recInstance recType recLen) x
      (flet ((blip (ext guid2 &optional metafileHeader)
               (with-stream (in (shorter-stream stream (RecordHeader.recLen x)))
                 (let* ((start (stream-position stream))
                        (end (+ start (RecordHeader.recLen x)))
                        (y (make-blip
                            :header x
                            :ext ext
                            :guid (read-guid in)
                            :guid2 (when (member recInstance guid2)
                                     (read-guid in))
                            :metafileHeader (if metafileHeader
                                                (read-OfficeArtMetafileHeader in)
                                                (read-octet in)))))
                   (when fn
                     (funcall fn y in))
                   (unless (eql end (stream-position stream))
                     (stream-position stream end))
                   y))))
        (ecase recType
          (#.RT_CurrentUserAtom
           (assert (zerop recVer))
           (assert (zerop recInstance))
           (list x (read-CurrentUserAtom stream))
           #+nil ;; why recLen too small?
           (with-shorter-stream (in stream (RecordHeader.recLen x))
             (list x (read-CurrentUserAtom in))))
          (#.RT_UserEditAtom
           (assert (zerop recVer))
           (assert (zerop recInstance))
           (with-stream (in (shorter-stream stream (RecordHeader.recLen x)))
             (list x (read-UserEditAtom in))))
          (#.RT_PersistDirectoryAtom
           (assert (zerop recVer))
           (assert (zerop recInstance))
           (let ((n (RecordHeader.recLen x)))
             ;;(print n)
             (with-stream (in (shorter-stream stream n))
               (make-PersistDirectoryAtom
                :header x
                :entries (loop
                            for fpos = 0 then (stream-position in)
                            while (< fpos n)
                            collect (progn
                                      ;;(print fpos)
                                      (read-PersistDirectoryEntry in)))))))
          #+nil
          (#.RT_Document ;; TODO
           )
          (#.RT_OfficeArtBlipEMF
           (assert (zerop recVer))
           (assert (member recInstance '(#x3d4 #x3d5)))
           (values (blip "emf" '(#x3d5) t) :emf))
          (#.RT_OfficeArtBlipWMF
           (assert (zerop recVer))
           (assert (member recInstance '(#x216 #x217)))
           (values (blip "wmf" '(#x217) t) :wmf))
          (#.RT_OfficeArtBlipPICT
           (assert (zerop recVer))
           (assert (member recInstance '(#x542 #x543)))
           (values (blip "pict" '(#x543) t) :pict))
          (#.RT_OfficeArtBlipJPEG1
           (assert (zerop recVer))
           (assert (member recInstance '(#x46A #x46B #x6E2 #x6E3)))
           (values (blip "jpeg" '(#x46B #x6E3)) :jpeg))
          (#.RT_OfficeArtBlipPNG
           (assert (zerop recVer))
           (assert (member recInstance '(#x6e0 #x6e1)))
           (values (blip "png"'(#x6e1)) :png))
          (#.RT_OfficeArtBlipDIB
           (assert (zerop recVer))
           (assert (member recInstance '(#x7a8 #x7a9)))
           (values (blip "dib" '(#x7a9)) :dib))
          (#.RT_OfficeArtBlipTIFF
           (assert (zerop recVer))
           (assert (member recInstance '(#x6e4 #x6e5)))
           (values (blip "tiff" '(#x6e5)) :tiff))
          (#.RT_OfficeArtBlipJPEG2
           (assert (zerop recVer))
           (assert (member recInstance '(#x46A #x46B #x6E2 #x6E3)))
           (values (blip "jpeg" '(#x46B #x6E3)) :jpeg)))))))

(defun read-record (stream &optional fn)
  (read-record-body stream (read-RecordHeader stream) fn))

(defun walk-RecordHeader-tree (ole-file entry fn &optional post-fn)
  (when entry
    (with-stream (in (ole-entry-stream ole-file entry))
      (labels ((rec (level pos parents)
                 (handler-case
                     (loop
                        for i from 0
                        until (<= 1 pos (stream-position in))
                        do (let* ((h (read-RecordHeader in))
                                  (start (stream-position in))
                                  (end (+ start (RecordHeader.recLen h))))
                             (funcall fn in level i h start end parents)
                             (if (= #xf (RecordHeader.recVer h))
                                 (rec (1+ level)
                                      (if (plusp pos)
                                          (min pos end)
                                          end)
                                      (cons h parents))
                                 (stream-position in end))
                             (when post-fn
                               (funcall post-fn in level i h start end parents))))
                   (end-of-file ()
                     (assert (zerop level))))))
        (rec 0 0 nil)))))

(defun print-RecordHeader-tree (ole-file entry)
  (walk-RecordHeader-tree
   ole-file
   entry
   (lambda (in level i h start end parents)
     (declare (ignore in parents))
     (dotimes (j (* 2 level))
       (write-char #\space))
     (format t "~d #x~x #x~x #x~x ~d :: ~d ~d :: ~a~%"
             i
             (RecordHeader.recVer h)
             (RecordHeader.recInstance h)
             (RecordHeader.recType h)
             (RecordHeader.recLen h)
             start
             end
             (enum-by-value 'RecordType (RecordHeader.recType h))))))

(defun print-RecordHeader-tree-from-ppt-file (filename)
  (with-stream (ole-file (ole-file-stream filename))
    (print-RecordHeader-tree
     ole-file
     (find-ole-entry ole-file :name "PowerPoint Document" :type 2))))

(defun utf-char (n)                ;; TODO utf properly
  (assert (plusp n))
  (if (member n '(#x0a #x0b #x0d)) ;; #x0b = vertical tab
      "<br/>"
      (code-char n)))

(defun ascii-char (n)
  (assert (plusp n))
  (if (member n '(#x0a #x0b #x0d)) ;; #x0b = vertical tab
      "<br/>"
      (code-char n)))

(define-structure OfficeArtFOPTEOPID ()
  (%dummy ushort)
  (opid t :compute (logand #x3fff %dummy))
  (fBid t :compute (not (zerop (logand #x4000 %dummy))))
  (fComplex t :compute (not (zerop (logand #x8000 %dummy)))))

(define-structure OfficeArtFBSE ()
  (btWin32 ubyte)
  (btMacOS ubyte)
  (rgbUid GUID)
  (tag ushort)
  (size dword)
  (cRef dword)
  (foDelay dword)
  (unused1 ubyte)
  (cbName ubyte)
  (unused2 ubyte)
  (unused3 ubyte)
  #+nil(nameData (ubyte cbName))
  #+nil(embeddedBlip (ubyte size)))

(defun ppt-entry-to-html-naive (ole-file entry stream title pictures debug)
  (macrolet ((out (&rest args)
               `(format stream ,@args)))
    (let ((slide-no 0)
          (blip-no 0)
          (blips nil)
          ;; texts
          (text-slide-no nil)
          (text-no nil)
          (texts nil))
      (out "<html>~%<head>~%")
      (when title
        (out "<title>~a</title>~%" title))
      (out "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>~%")
      (out "<style>~%")
      (out ".h {border-left:1px solid gray;padding-left:0.5em}~%")
      (out ".m {color:gray}")
      (out "</style>~%")
      (out "</head>~%<body>~%")
      (when title
        (out "<a href=\"file://~a\">~a</a>~%" title title))
      (walk-RecordHeader-tree
       ole-file
       entry
       (lambda (in level i h start end parents)
         (declare (ignore end))
         (when debug
           ;; pre
           (when (and (zerop level) (plusp i))
             (out "<hr/>~%"))
           ;; msg
           (when debug
             (out "<div class=\"h\">~%<pre class=\"m\">~a ~a #x~x ~a</pre>~%"
                  (- start 8) ;; - record header size
                  (RecordHeader.recType h)
                  (RecordHeader.recType h)
                  (enum-by-value 'RecordType (RecordHeader.recType h)))))
         ;; post
         (case (RecordHeader.recType h)
           (#.RT_Document)
           (#.RT_SlideListWithText
            (setq text-slide-no 0))
           (#.RT_SlidePersistAtom
            (incf text-slide-no)
            (setq text-no 0))
           (#.RT_OfficeArtFBSE
            (let* ((x (read-OfficeArtFBSE in))
                   (y (find (OfficeArtFBSE.foDelay x) pictures :key #'cadr)))
              (assert y)
              (push (list (incf blip-no) (car y) (caddr y)) blips)
              #+nil
              (out "<div><p>@@@ ~a #x~x ~a === img ~s ~s</p>~%"
                   (RecordHeader.recType h)
                   (RecordHeader.recType h)
                   (enum-by-value 'RecordType (RecordHeader.recType h))
                   blip-no
                   (OfficeArtFBSE.foDelay x))))
           (#.RT_Slide
            (incf slide-no)
            (unless debug
              (when (< 1 slide-no)
                (out "<hr/>~%")))
            (out "<div class=\"slide\">~%")
            (out "<h1><a name=\"slide~d\">Slide ~d</a></h1>~%" slide-no slide-no)
            (out "<pre><a href=\"#slide~d\">&lt;</a> <a href=\"#slide~d\">&gt;</a></pre>~%" (1- slide-no) (1+ slide-no)))
           ((#.RT_TextCharsAtom #.RT_CString) ;; utf16le
            (unless nil #+nil(or (member #.RT_PROGTAGS parents :key 'RecordHeader.recType)
                        (member #.RT_NOTES parents :key 'RecordHeader.recType)
                        (member #.RT_MAINMASTER parents :key 'RecordHeader.recType))
              (cond
                #+nil
                ((member #.RT_SlideListWithText parents :key 'RecordHeader.recType)
                 (push ;; TODO also slide-no + text-no inside slide
                  (list
                   text-slide-no
                   (incf text-no)
                   (with-output-to-string (s)
                     (loop
                        for j from 0 below (RecordHeader.recLen h) by 2
                        do (format s "~a" (utf-char (read-ushort in))))))
                  texts))
                (t
                 (out "<p>")
                 (loop
                    for j from 0 below (RecordHeader.recLen h) by 2
                    do (out "~a" (utf-char (read-ushort in))))
                 (out "</p>~%")))))
           (#.RT_TextBytesAtom ;; ascii
            (unless nil #+nil(or (member #.RT_PROGTAGS parents :key 'RecordHeader.recType)
                        (member #.RT_NOTES parents :key 'RecordHeader.recType)
                        (member #.RT_MAINMASTER parents :key 'RecordHeader.recType))
              (cond
                #+nil
                ((member #.RT_SlideListWithText parents :key 'RecordHeader.recType)
                 (push ;; TODO also slide-no + text-no inside slide
                  (list
                   text-slide-no
                   (incf text-no)
                   (with-output-to-string (s)
                     (loop
                        for j from 0 below (RecordHeader.recLen h)
                        do (format s "~a" (ascii-char (read-octet in))))))
                  texts))
                (t
                 (out "<p>")
                 (loop
                    for j from 0 below (RecordHeader.recLen h)
                    do (out "~a" (ascii-char (read-octet in))))
                 (out "</p>~%")))))
           (#.RT_OUTLINETEXTREFATOM
            (let* ((index (1+ (read-dword in)))
                   (text (caddr
                          (find-if (lambda (x)
                                     (and (= slide-no (car x))
                                          (= index (cadr x))))
                                   texts))))
              (if text
                  (out "<p>~a</p>~%" text)
                  (out "<p>!!!</p>~%"))))
           ;; TODO RT_DOCUMENT / RT_SLIDELISTWITHTEXT / RT_TEXTBYTESATOM
           (#.RT_OfficeArtFOPT
            (with-stream (s (shorter-stream in (RecordHeader.recLen h)))
              (let ((len (RecordHeader.recLen h)))
                (loop
                   while (< (stream-position s) len)
                   do (let ((opid (read-OfficeArtFOPTEOPID s))
                            (value (read-dword s)))
                        ;;(out "<p>...... ~s ~s</p>~%" opid value)
                        (when (OfficeArtFOPTEOPID.fComplex opid)
                          (decf len value))
                        (case (OfficeArtFOPTEOPID.opid opid)
                          (#.pib
                           (assert (OfficeArtFOPTEOPID.fBid opid))
                           (destructuring-bind (j n ext) (assoc value blips)
                             (assert (and j n ext))
                             (out "<img src=\"~a.~(~a~)\"/>~%" n ext)))))))))))
       (lambda (in level i h start end parents)
         (declare (ignore in level i start end parents))
         (case (RecordHeader.recType h)
           (#.RT_Slide
            (out "</div>~%")))
         (when debug
           (format stream "</div>~%"))))
      ;;(out "~s~%" texts)
      (out "</body>~%</html>~%"))))

(defun ppt-file-to-html-naive (filename &optional (stream *standard-output*))
  (with-stream (ole-file (ole-file-stream filename))
    (let ((pictures nil))
      ;;(extract-pictures ole-file dir html) ;; TODO mount olefs and traverse Pictures only once
      (walk-RecordHeader-tree ole-file
                              (find-ole-entry ole-file :name "Pictures" :type 2)
                              (lambda (in level i h start end parents)
                                (declare (ignore level end parents))
                                (multiple-value-bind (blip kind)
                                    (read-record-body in h)
                                  (declare (ignore blip))
                                  (push (list i (- start 8) kind) pictures))))
      (ppt-entry-to-html-naive ole-file
                               (find-ole-entry ole-file
                                               :name "PowerPoint Document"
                                               :type 2)
                               stream
                               filename
                               pictures
                               t))))

(define-structure UserEditAtom ()
  (lastSlideIdRef dword)
  (version ushort)
  (minorVersion ubyte :always 0)
  (majorVersion ubyte :always 3)
  (offsetLastEdit dword)
  (offsetPersistDirectory dword)
  (docPersistIdRef dword :always 1)
  (persistIdSeed dword)
  (lastView ushort)
  (unused ushort)
  #+nil(encryptSessionPersistIdRef dword)) ;; TODO optional

(defun ppt-entry-to-html (ole-file entry stream title)
  (macrolet ((out (&rest args)
               `(format stream ,@args)))
    (let ((slide-no 0))
      (out "<html>~%<head>~%")
      (when title
        (out "<title>~a</title>~%" title))
      (out "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>~%")
      (out "</head>~%<body>~%")
      (walk-RecordHeader-tree
       ole-file
       entry
       (lambda (in level i h start end parents)
         (declare (ignore i level start end parents))
         (case (RecordHeader.recType h)
           (#.RT_Document
            (out "<div>~%"))
           (#.RT_Slide
            (out "<hr/>~%</div>~%<div class=\"slide\">~%<h1>Slide ~d</h1>~%" (incf slide-no)))
           ((#.RT_TextCharsAtom #.RT_CString) ;; utf16le
            (out "<p>")
            (loop
               for j from 0 below (RecordHeader.recLen h) by 2
               do (out "~a" (utf-char (read-ushort in))))
            (out "</p>~%"))
           (#.RT_TextBytesAtom ;; ascii
            (out "<p>")
            (loop
               for j from 0 below (RecordHeader.recLen h)
               do (out "~a" (ascii-char (read-octet in))))
            (out "</p>~%")))))
      (out "</div>~%</body>~%</html>~%"))))

(defun process-PersistDirectoryAtom (htab in)
  (dolist (entry (PersistDirectoryAtom-entries (read-record in)))
    (with-slots (persistId cPersist rgPersistOffset) entry
      (loop
         for n from 0
         for o across rgPersistOffset
         do (let ((k (+ persistId n)))
              ;;(print (list :??? persistId :+ n := k :-> o))
              (unless (gethash k htab)
                ;;(print (list persistId :+ n := k :-> o))
                (setf (gethash k htab) o)))))))

(defun ppt-file-to-html (filename &optional (stream *standard-output*))
  (with-stream (ole-file (ole-file-stream filename))
    (let ((u (block CurrentUser
               (walk-RecordHeader-tree
                ole-file
                (find-ole-entry ole-file :name "Current User" :type 2)
                (lambda (in level i h start end parents)
                  (declare (ignore level i start end parents))
                  (return-from CurrentUser
                    (cadr (read-record-body in h))))))))
      ;;(describe u)
      (let ((pictures nil))
        ;;(extract-pictures ole-file dir html) ;; TODO mount olefs and traverse Pictures only once
        (walk-RecordHeader-tree ole-file
                                (find-ole-entry ole-file
                                                :name "Pictures"
                                                :type 2)
                                (lambda (in level i h start end parents)
                                  (declare (ignore level end parents))
                                  (multiple-value-bind (blip kind)
                                      (read-record-body in h)
                                    (declare (ignore blip))
                                    (push (list i (- start 8) kind) pictures))))
        (print (list :pictures pictures))
        (with-stream (in (ole-entry-stream
                          ole-file
                          (find-ole-entry ole-file
                                          :name "PowerPoint Document"
                                          :type 2)))
          (let ((htab (make-hash-table)) ;; persist oid -> fpos
                (first-UserEditAtom nil))
            (stream-position in (CurrentUserAtom.offsetToCurrentEdit u))
            (loop
               for e = (cadr (read-record in)) then (cadr (read-record in))
               do (progn
                    ;;(describe e)
                    (unless first-UserEditAtom
                      (setq first-UserEditAtom e))
                    (stream-position in (UserEditAtom.offsetPersistDirectory e))
                    (process-PersistDirectoryAtom htab in))
               until (zerop (UserEditAtom.offsetLastEdit e))
               do (stream-position in (UserEditAtom.offsetLastEdit e)))
            ;; live PersistDirectory
            (let ((persist-directory nil))
              (maphash (lambda (k v) (push (cons k v) persist-directory)) htab)
              (setq persist-directory (sort persist-directory #'< :key #'car))
              (print persist-directory))
            ;; live DocumentContainer
            (print (gethash (UserEditAtom.docPersistIdRef first-UserEditAtom) htab)))
          #+nil(stream-position in 0)
          #+nil(print (read-record in)))))))

;;; MS-DOC Word (.doc) Binary File Format

(define-structure FibBase ()
  (wIdent ushort)
  (nFib ushort)
  (unused ushort)
  (lid ushort)
  (pnNext ushort)
  (flags1 ushort) ;; TODO
  (nFibBack ushort :member '(#xbf #xc1))
  (lKey dword)
  (envr ubyte)       ;; TODO :always 0?
  (flags2 ubyte)     ;; TODO
  (reserved3 ushort) ;; TODO :always 0?
  (reserved4 ushort) ;; TODO :always 0?
  (reserved5 dword)
  (reserved6 dword))

(define-structure FibRgFcLcb97 ()
  (fcStshfOrig dword)
  (lcbStshfOrig dword)
  (fcStshf dword)
  (lcbStshf dword)
  (fcPlcffndRef dword)
  (lcbPlcffndRef dword)
  (fcPlcffndTxt dword)
  (lcbPlcffndTxt dword)
  (fcPlcfandRef dword)
  (lcbPlcfandRef dword)
  (fcPlcfandTxt dword)
  (lcbPlcfandTxt dword)
  (fcPlcfSed dword)
  (lcbPlcfSed dword)
  (fcPlcPad dword)
  (lcbPlcPad dword)
  (fcPlcfPhe dword)
  (lcbPlcfPhe dword)
  (fcSttbfGlsy dword)
  (lcbSttbfGlsy dword)
  (fcPlcfGlsy dword)
  (lcbPlcfGlsy dword)
  (fcPlcfHdd dword)
  (lcbPlcfHdd dword)
  (fcPlcfBteChpx dword)
  (lcbPlcfBteChpx dword)
  (fcPlcfBtePapx dword)
  (lcbPlcfBtePapx dword)
  (fcPlcfSea dword)
  (lcbPlcfSea dword)
  (fcSttbfFfn dword)
  (lcbSttbfFfn dword)
  (fcPlcfFldMom dword)
  (lcbPlcfFldMom dword)
  (fcPlcfFldHdr dword)
  (lcbPlcfFldHdr dword)
  (fcPlcfFldFtn dword)
  (lcbPlcfFldFtn dword)
  (fcPlcfFldAtn dword)
  (lcbPlcfFldAtn dword)
  (fcPlcfFldMcr dword)
  (lcbPlcfFldMcr dword)
  (fcSttbfBkmk dword)
  (lcbSttbfBkmk dword)
  (fcPlcfBkf dword)
  (lcbPlcfBkf dword)
  (fcPlcfBkl dword)
  (lcbPlcfBkl dword)
  (fcCmds dword)
  (lcbCmds dword)
  (fcUnused1 dword)
  (lcbUnused1 dword)
  (fcSttbfMcr dword)
  (lcbSttbfMcr dword)
  (fcPrDrvr dword)
  (lcbPrDrvr dword)
  (fcPrEnvPort dword)
  (lcbPrEnvPort dword)
  (fcPrEnvLand dword)
  (lcbPrEnvLand dword)
  (fcWss dword)
  (lcbWss dword)
  (fcDop dword)
  (lcbDop dword)
  (fcSttbfAssoc dword)
  (lcbSttbfAssoc dword)
  (fcClx dword)
  (lcbClx dword)
  (fcPlcfPgdFtn dword)
  (lcbPlcfPgdFtn dword)
  (fcAutosaveSource dword)
  (lcbAutosaveSource dword)
  (fcGrpXstAtnOwners dword)
  (lcbGrpXstAtnOwners dword)
  (fcSttbfAtnBkmk dword)
  (lcbSttbfAtnBkmk dword)
  (fcUnused2 dword)
  (lcbUnused2 dword)
  (fcUnused3 dword)
  (lcbUnused3 dword)
  (fcPlcSpaMom dword)
  (lcbPlcSpaMom dword)
  (fcPlcSpaHdr dword)
  (lcbPlcSpaHdr dword)
  (fcPlcfAtnBkf dword)
  (lcbPlcfAtnBkf dword)
  (fcPlcfAtnBkl dword)
  (lcbPlcfAtnBkl dword)
  (fcPms dword)
  (lcbPms dword)
  (fcFormFldSttbs dword)
  (lcbFormFldSttbs dword)
  (fcPlcfendRef dword)
  (lcbPlcfendRef dword)
  (fcPlcfendTxt dword)
  (lcbPlcfendTxt dword)
  (fcPlcfFldEdn dword)
  (lcbPlcfFldEdn dword)
  (fcUnused4 dword)
  (lcbUnused4 dword)
  (fcDggInfo dword)
  (lcbDggInfo dword)
  (fcSttbfRMark dword)
  (lcbSttbfRMark dword)
  (fcSttbfCaption dword)
  (lcbSttbfCaption dword)
  (fcSttbfAutoCaption dword)
  (lcbSttbfAutoCaption dword)
  (fcPlcfWkb dword)
  (lcbPlcfWkb dword)
  (fcPlcfSpl dword)
  (lcbPlcfSpl dword)
  (fcPlcftxbxTxt dword)
  (lcbPlcftxbxTxt dword)
  (fcPlcfFldTxbx dword)
  (lcbPlcfFldTxbx dword)
  (fcPlcfHdrtxbxTxt dword)
  (lcbPlcfHdrtxbxTxt dword)
  (fcPlcffldHdrTxbx dword)
  (lcbPlcffldHdrTxbx dword)
  (fcStwUser dword)
  (lcbStwUser dword)
  (fcSttbTtmbd dword)
  (lcbSttbTtmbd dword)
  (fcCookieData dword)
  (lcbCookieData dword)
  (fcPgdMotherOldOld dword)
  (lcbPgdMotherOldOld dword)
  (fcBkdMotherOldOld dword)
  (lcbBkdMotherOldOld dword)
  (fcPgdFtnOldOld dword)
  (lcbPgdFtnOldOld dword)
  (fcBkdFtnOldOld dword)
  (lcbBkdFtnOldOld dword)
  (fcPgdEdnOldOld dword)
  (lcbPgdEdnOldOld dword)
  (fcBkdEdnOldOld dword)
  (lcbBkdEdnOldOld dword)
  (fcSttbfIntlFld dword)
  (lcbSttbfIntlFld dword)
  (fcRouteSlip dword)
  (lcbRouteSlip dword)
  (fcSttbSavedBy dword)
  (lcbSttbSavedBy dword)
  (fcSttbFnm dword)
  (lcbSttbFnm dword)
  (fcPlfLst dword)
  (lcbPlfLst dword)
  (fcPlfLfo dword)
  (lcbPlfLfo dword)
  (fcPlcfTxbxBkd dword)
  (lcbPlcfTxbxBkd dword)
  (fcPlcfTxbxHdrBkd dword)
  (lcbPlcfTxbxHdrBkd dword)
  (fcDocUndoWord9 dword)
  (lcbDocUndoWord9 dword)
  (fcRgbUse dword)
  (lcbRgbUse dword)
  (fcUsp dword)
  (lcbUsp dword)
  (fcUskf dword)
  (lcbUskf dword)
  (fcPlcupcRgbUse dword)
  (lcbPlcupcRgbUse dword)
  (fcPlcupcUsp dword)
  (lcbPlcupcUsp dword)
  (fcSttbGlsyStyle dword)
  (lcbSttbGlsyStyle dword)
  (fcPlgosl dword)
  (lcbPlgosl dword)
  (fcPlcocx dword)
  (lcbPlcocx dword)
  (fcPlcfBteLvc dword)
  (lcbPlcfBteLvc dword)
  (dwLowDateTime dword)
  (dwHighDateTime dword)
  (fcPlcfLvcPre10 dword)
  (lcbPlcfLvcPre10 dword)
  (fcPlcfAsumy dword)
  (lcbPlcfAsumy dword)
  (fcPlcfGram dword)
  (lcbPlcfGram dword)
  (fcSttbListNames dword)
  (lcbSttbListNames dword)
  (fcSttbfUssr dword)
  (lcbSttbfUssr dword))

#+nil
(define-structure FibRgCswNew ()
  (nFibNew ushort :member '(#x00D9 #x0101 #x010C #x0112))
  rgCswNewData (variable): Depending on the value of nFibNew this is one of the following.
  Value of nFibNew
  Meaning
  0x00D9
  fibRgCswNewData2000 (2 bytes)
  0x0101
  fibRgCswNewData2000 (2 bytes)
  0x010C
  fibRgCswNewData2000 (2 bytes)
  0x0112
  fibRgCswNewData2007 (8 bytes) )

(defstruct fib base csw fibRgW cslw fibRgLw cbRgFcLcb fibRgFcLcbBlob fibRgFcLcb
           cswNew fibRgCswNew)

(defun read-fib (stream)
  (let* ((base (read-fibbase stream))
         (csw (let ((x (read-ushort stream)))
                (assert (= x #x0e))
                x))
         (fibRgW (read-vector stream 28 '(unsigned-byte 8) 'read-octet))
         (cslw (let ((x (read-ushort stream)))
                 (assert (= x #x16))
                 x))
         (fibRgLw (read-vector stream 88 '(unsigned-byte 8) 'read-octet))
         (cbRgFcLcb (read-ushort stream))
         (fibRgFcLcbBlob-position (stream-position stream))
         (fibRgFcLcbBlob (read-vector stream (* 8 cbRgFcLcb) '(unsigned-byte 8) 'read-octet))
         (cswNew (read-ushort stream))
         (fibRgCswNew (read-vector stream cswNew '(unsigned-byte 8) 'read-octet))
         #+nil
         (nFib (if (zerop cswNew)
                   (FibBase.nFib base)
                   -1 #+nil(assert (zerop cswNew))))) ;; TODO implement this case
    (assert
     (member cbRgFcLcb '(#x5d #x6c #x88 #xa4 #xb7))
     #+nil ;; spec says as bellow:-{
     (= cbRgFcLcb (ecase nFib
                    (#x0c1 #x5d) ;;;; < should be
                    (#x0d9 #x6c)
                    (#x101 #x88)
                    (#x10c #xa4) ;;;; < actually is
                    (#x112 #xb7))))
    #+nil
    (assert (= cswNew (ecase nFib
                        (#x0c1 0)
                        (#x0d9 2)
                        (#x101 2)
                        (#x10c 2)
                        (#x112 5))))
    ;;(print (list :@@@-nfib nFib))
    (make-fib :base base
              :csw csw
              :fibRgW fibRgW
              :cslw cslw
              :fibRgLw fibRgLw
              :cbRgFcLcb cbRgFcLcb
              :fibRgFcLcbBlob fibRgFcLcbBlob
              :fibRgFcLcb (with-stream (s (vector-stream fibRgFcLcbBlob
                                                         fibRgFcLcbBlob-position))
                            (read-FibRgFcLcb97 s))
              :cswNew cswNew
              :fibRgCswNew fibRgCswNew)))

(define-structure LSTF ()
  (lsid dword) ;; TODO signed, not -1 (or #xffffffff)
  (tplc dword)
  (rgistdPara (ushort 9))
  (flags ubyte)
  (fSimpleList t :compute (not (zerop (logand #x01 flags))))
  (unused1 t :compute (not (zerop (logand #x02 flags))))
  (fAutoNum t :compute (not (zerop (logand #x04 flags))))
  (unused2 t :compute (not (zerop (logand #x08 flags))))
  (fHybrid t :compute (not (zerop (logand #x10 flags))))
  (reserved1 t :compute (logand #xe0 flags)) ;; TODO :always 0
  (grfhic ubyte))

(defun read-PlfLst (stream)
  (let* ((cLst (read-ushort stream))
         (z (make-array cLst)))
    (dotimes (i cLst z)
      (setf (aref z i) (read-lstf stream)))))

(define-structure LVLF ()
  (iStartAt dword) ;; TODO signed
  (nfc ubyte) ;; TODO MUST not be equal to 0x08, 0x09, 0x0F, or 0x13
  (flags ubyte)
  (jc t :compute (logand #x03 flags))
  (fLegal t :compute (not (zerop (logand #x04 flags))))
  (fNoRestart t :compute (not (zerop (logand #x08 flags))))
  (fIndentSav t :compute (not (zerop (logand #x10 flags))))
  (fConverted t :compute (not (zerop (logand #x20 flags))))
  (unused1 t :compute (not (zerop (logand #x40 flags))))
  (fTentative t :compute (not (zerop (logand #x80 flags))))
  (rgbxchNums (ubyte 9))
  (ixchFollow ubyte)
  (dxaIndentSav dword) ;; TODO signed
  (unused2 dword)
  (cbGrpprlChpx ubyte)
  (cbGrpprlPapx ubyte)
  (ilvlRestartLim ubyte)
  (grfhic ubyte))

(defstruct LVL lvlf grpprlPapx grpprlChpx xst)

(define-structure Sprm ()
  (flags ushort)
  (ispmd t :compute (logand #x01ff flags))
  (fSpec t :compute (not (zerop (logand #x0200 flags))))
  (sgc t :compute (logand #x07 (ash flags -10)))
  (spra t :compute (logand #x07 (ash flags -13))))

(defstruct PChgTabsDelClose cTabs rgdxaDel rgdxaClose)

(defun read-PChgTabsDelClose (stream)
  (let ((cTabs (read-octet stream)))
    (assert (<= 0 cTabs 64))
    (let ((rgdxaDel (read-vector stream cTabs t 'read-ushort))
          (rgdxaClose (read-vector stream cTabs t 'read-ushort)))
      (assert (equalp rgdxaDel (sort (copy-seq rgdxaDel) #'<=)))
      (make-PChgTabsDelClose :cTabs cTabs
                             :rgdxaDel rgdxaDel
                             :rgdxaClose rgdxaClose))))

(defstruct PChgTabsAdd cTabs rgdxaAdd rgtbdAdd)

(defun read-PChgTabsAdd (stream)
  (let ((cTabs (read-octet stream)))
    (assert (<= 0 cTabs 64))
    (let ((rgdxaAdd (read-vector stream cTabs t 'read-ushort))
          (rgtbdAdd (read-vector stream cTabs t 'read-octet))) ;; TODO decode TBD struct
      (assert (equalp rgdxaAdd (sort (copy-seq rgdxaAdd) #'<=)))
      (make-PChgTabsAdd :cTabs cTabs
                        :rgdxaAdd rgdxaAdd
                        :rgtbdAdd rgtbdAdd))))

(defstruct PChgTabsOperand cb DelClose Add)

(defun read-PChgTabsOperand (stream)
  (let ((cb (read-octet stream)))
    (assert (< 1 cb 255)) ;; TODO 255
    ;;(read-vector stream cb t 'read-octet)
    (make-PChgTabsOperand :cb cb
                          :DelClose (read-PChgTabsDelClose stream)
                          :Add (read-PChgTabsAdd stream))))

(defstruct Prl sprm operand)

(defun read-Prl (stream)
  (let ((sprm (read-Sprm stream)))
    ;; (when (zerop (Sprm.sgc sprm))
    ;;   (print (list :@@@-!!! (read-vector stream 10 t 'read-octet))))
    (assert (member (Sprm.sgc sprm) '(1 2 3 4 5)))
    (make-Prl
     :sprm sprm
     :operand (ecase (Sprm.spra sprm)
                (0 (read-octet stream))
                (1 (read-octet stream))
                (2 (read-ushort stream))
                (3 (read-dword stream))
                (4 (read-ushort stream))
                (5 (read-ushort stream))
                (6 (flet ((rd ()
                            (read-vector stream (read-octet stream) t 'read-octet)))
                     (ecase (Sprm.sgc sprm)
                       (1 (ecase (Sprm.flags sprm) ;; par
                            (#xc615 (read-PChgTabsOperand stream))))
                       (2 (rd))     ;; char
                       (3 (rd))     ;; pic
                       (4 (rd))     ;; sec
                       #+nil(5 )))) ;; tab
                (7 (read-vector stream 3 t 'read-octet))))))

(defstruct Xst blob parsed)

(defun read-Xst (stream)
  ;;(read-vector stream (read-ushort stream) t 'read-ushort)
  (let* ((cch (read-ushort stream))
         (blob (read-vector stream cch t 'read-ushort)))
    (make-Xst :blob blob
              :parsed nil
              #+nil(with-output-to-string (out)
                     (dotimes (i cch)
                       (format out "~a" (utf-char (aref blob i))))))))

(defun read-LVL (stream)
  (let ((lvlf (read-lvlf stream)))
    ;;(describe lvlf)
    (make-LVL
     :lvlf lvlf
     :grpprlPapx (read-vector stream (LVLF.cbGrpprlPapx lvlf) t 'read-octet)
     :grpprlChpx (read-vector stream (LVLF.cbGrpprlChpx lvlf) t 'read-octet)
     ;; :grpprlPapx (read-vector stream (LVLF.cbGrpprlPapx lvlf) t 'read-prl)
     ;; :grpprlChpx (read-vector stream (LVLF.cbGrpprlChpx lvlf) t 'read-prl)
     :xst (read-Xst stream))))

(defun fix-numbering (filename)
  (let (offsets)
    (with-stream (ole-file (ole-file-stream filename))
      #+nil(break "~s" ole-file)
      (let (fcPlfLst lcbPlfLst)
        (with-stream (in (ole-entry-stream
                          ole-file
                          (find-ole-entry ole-file
                                          :name "WordDocument"
                                          :type 2)))
          (let ((fib (read-fib in)))
            ;;(describe fib)
            (let ((x (fib-fibRgFcLcb fib)))
              (setq fcPlfLst (FibRgFcLcb97.fcPlfLst x)
                    lcbPlfLst (FibRgFcLcb97.lcbPlfLst x)))
            #+nil
            (multiple-value-bind (fcPlfLst lcbPlfLst)
                (with-stream (s (vector-stream (subseq (fib-fibRgFcLcbBlob fib) #.(* 4 146))))
                  (values (read-dword s) (read-dword s)))
              (print (list :@@@ fcPlfLst lcbPlfLst))
              )))
        (with-stream (in (ole-entry-stream
                          ole-file
                          (find-ole-entry ole-file
                                          :name '("0Table" "1Table") ;; TODO be sure which one?
                                          :type 2)))
          (stream-position in fcPlfLst)
          (let ((PlfLst (read-PlfLst in)))
            (let ((n 0))
              (dotimes (i (length PlfLst))
                (incf n (if (LSTF.fSimpleList (aref PlfLst i)) 1 9)))
              (let ((lvls (make-array n)))
                (dotimes (i n)
                  (setf (aref lvls i) (read-lvl in)))
                ;; now I have lstf[] and lvl[]
                (let (anums ;; roughly like w:abstractNum
                      (j 0))
                  (dotimes (i (length PlfLst))
                    (let ((lstf (aref PlfLst i)))
                      (unless (LSTF.fSimpleList lstf)
                        (push (list i #+nil lstf j) anums))
                      (incf j (if (LSTF.fSimpleList lstf) 1 9))))
                  (setq anums (nreverse anums))
                  ;;(print anums)
                  (dolist (a anums)
                    (destructuring-bind (i j) a ;; i_lstf j_lvl0
                      (declare (ignore i))
                      (let* ((lvl (aref lvls (1+ j))) ;; hardcode second level
                             (lvlf (LVL-lvlf lvl)))
                        ;;(print (list :@@@ j (LVLF.fNoRestart lvlf) (LVLF.ilvlRestartLim lvlf)))
                        (push (LVLF.%physical-stream-position lvlf) offsets)))))
                #+nil
                (dotimes (i n)
                  (let* ((lvl (aref lvls i))
                         (lvlf (LVL-lvlf lvl)))
                    (print (list :@@@ i (LVLF.fNoRestart lvlf) (LVLF.ilvlRestartLim lvlf)))))))))
        #+nil(values fcPlfLst lcbPlfLst)))
    (let ((fixed (format nil "~a.fixed.doc" filename)))
      (copy-file filename fixed)
      ;;(print (list :@@@-offsets offsets))
      (with-open-file (s fixed
                         :direction :io
                         :if-exists :overwrite
                         :if-does-not-exist :error
                         :element-type '(unsigned-byte 8))
        (dolist (o offsets)
          (stream-position s (+ 5 o))
          (let ((flags (read-octet s)))
            (stream-position s (+ 5 o))
            (write-byte (logior #x08 flags) s)
            #+nil(write-byte (logand #x07 flags) s))
          (stream-position s (+ 26 o))
          (write-byte 0 s))))))

(defun extract-files (filename &optional (dir "/tmp"))
  (with-stream (ole-file (ole-file-stream filename))
    (do ((s (ole-directory-stream ole-file))
         e
         (i 0))
        ((not (setq e (funcall s))))
      (print-ole-entry e *standard-output*)
      (terpri)
      (ecase (ole-entry.object-type e)
        ((0 1 5))
        (2 (with-stream (in (ole-entry-stream ole-file e))
             (with-open-file (out (format nil "~a/XX-~d" dir (incf i))
                                  :direction :output
                                  :if-does-not-exist :create
                                  :if-exists :supersede
                                  :element-type '(unsigned-byte 8))
               (copy-stream in out))))))))

;;; MS-XLS Excel binary file

(define-structure BIFFRecordHeader ()
  (tag ushort)
  (length ushort))

(define-structure BIFF-ShortXLUnicodeString ()
  (cch ubyte)
  (%dummy ubyte :member '(0 1))
  (fHighByte t :compute (not (zerop (logand 1 %dummy))))
  (reserved1 t :compute (assert (zerop (logand #xfe %dummy))))
  (rgb (ubyte (if fHighByte (* 2 cch) cch)))
  (decoded t :compute (string-from-octets rgb fHighByte)))

(define-structure BIFF-BoundSheet8 ()
  (lbPlyPos dword)
  (hsState ubyte :member '(0 1 2))
  (dt ubyte :member '(0 1 2 6))
  (stName BIFF-ShortXLUnicodeString))

(define-structure BIFF-Cell ()
  (rw ushort)
  (col ushort)
  (ixfe ushort))

(define-structure BIFF-Blank ()
  (cell BIFF-Cell))

(define-structure BIFF-RkNumber ()
  (%dummy dword)
  (percent t :compute (not (zerop (logand 1 %dummy))))
  (signed t :compute (not (zerop (logand 2 %dummy))))
  (value t :compute (let ((y (if signed
                                 (error "TODO") ;;(ash x -2)
                                 (double-float-from-bits
                                  (logand #xfffffffc %dummy) 0))))
                      (if percent (/ y 100) y))))

(define-structure BIFF-RkRec ()
  (ixfe ushort)
  (rk BIFF-RkNumber))

(define-structure BIFF-RK ()
  (rw ushort)
  (col ushort)
  (rkRec BIFF-RkRec))

(define-structure BIFF-Bes ()
  (bBoolErr ubyte)
  (fError ubyte :member '(0 1))
  (decoded t :compute (if (zerop fError)
                          (ecase bBoolErr
                            (0 nil)
                            (1 t))
                          (ecase fError
                            (0 :#NULL!)
                            (7 :#DIV/0!)
                            (#xf :#VALUE!)
                            (#x17 :#REF!)
                            (#x1d :#NAME!)
                            (#x24 :#NUM!)
                            (#x2a :#N/A)
                            (#x2b :#GETTING_DATA)))))

(define-structure BIFF-BoolErr ()
  (cell BIFF-Cell)
  (bes BIFF-Bes))

(define-structure BIFF-Number ()
  (cell BIFF-Cell)
  (num ulonglong)) ;; TODO double

(define-structure BIFF-LabelSst ()
  (cell BIFF-Cell)
  (isst dword))

(define-structure BIFF-FormulaValue () ;; TODO
  (byte1 ubyte)
  (byte2 ubyte)
  (byte3 ubyte)
  (byte4 ubyte)
  (byte5 ubyte)
  (byte6 ubyte)
  (fExprO ushort))

#+nil
(define-structure BIFF-CellParsedFormula () ;; TODO
  (cce ushort)
  (rgce (ubyte cce))
  (rgcb BIFF-RgbExtra))

#+nil
(define-structure BIFF-Formula () ;; TODO also probably wrong bit fiddling
  (cell BIFF-Cell)
  (val BIFF-FormulaValue)
  (%dummy ushort)
  (fAlwaysCalc t :compute (not (zerop (logand #x8000))))
  (reserved1 t :compute (assert (zerop (logand #x4000))))
  (fFill t :compute (not (zerop (logand #x2000))))
  (fShrFmla t :compute (not (zerop (logand #x1000))))
  (reserved2 t :compute (assert (zerop (logand #x800))))
  (fClearErrors t :compute (not (zerop (logand #x400))))
  (reserved3 t :compute (assert (zerop (logand #x3ff))))
  (chn dword)
  (formula BIFF-CellParsedFormula))

#+nil
(define-structure BIFF-MulBlank () ;; TODO
  (rw ushort)
  (colFirst ushort))

(define-structure BIFF-FormatRun ()
  (ich ushort)
  (ifnt ushort))

(define-structure BIFF-LPWideString ()
  (cchCharacters ushort)
  (rgchData (wchar cchCharacters))
  (decoded t :compute (string-from-wchars rgchData)))

(define-structure BIFF-RPHSSub ()
  (crun ushort)
  (cch ushort)
  (st BIFF-LPWideString))

(define-structure BIFF-ExtRst ()
  (reserved ushort)
  (cb ushort)
  (phs dword)
  (rphssub BIFF-RPHSSub)
  (rgphruns (PhRuns (BIFF-RPHSSub.crun rphssub))))

(defvar *fHighByte*) ;; nil|0|1 ;; TODO clean up nil|t vs nil|0|1

(defun read-ustring (stream nchars fHighByte)
  (let ((*fHighByte* fHighByte)
        (b (make-array (* 2 nchars)
                       :element-type 'character
                       :fill-pointer 0)))
    (dotimes (i nchars (coerce b 'string))
      (vector-push-extend
       (code-char (let ((c (ecase *fHighByte*
                             (0 (read-octet stream))
                             (1 (logior (read-octet stream)
                                        (ash (read-octet stream) 8))))))
                    (assert (plusp c))
                    c))
       b))))

(define-structure BIFF-XLUnicodeRichExtendedString ()
  (cch ushort)
  (%dummy ubyte)
  (fHighByte t :compute (logand 1 %dummy))
  (reserved1 t :compute (assert (zerop (logand 2 %dummy))))
  (fExtSt t :compute (not (zerop (logand 4 %dummy))))
  (fRichSt t :compute (not (zerop (logand 8 %dummy))))
  (reserved2 t :compute (assert (zerop (logand #xf0 %dummy))))
  (cRun ushort :when fRichSt :default 0)
  (cbExtRst dword :when fExtSt :default 0)
  (rgb t :compute (read-ustring stream cch fHighByte))
  (rgRun (BIFF-FormatRun cRun) :when fRichSt :default #())
  (ExtRst (BIFF-ExtRst cbExtRst) :when fExtSt :default #()))

(define-structure BIFF-SST ()
  (cstTotal dword)
  (cstUnique dword)
  (rgb (BIFF-XLUnicodeRichExtendedString cstUnique)))

(define-structure BIFF-DefColWidth ()
  (cchdefColWidth ushort))

(define-structure BIFF-Index ()
  (reserved dword :always 0)
  (rwMic dword)
  (rwMac dword)
  (ibXF dword)
  (rgibRw (dword 1)))

(defun biff-continue-stream (stream size)
  ;; like SHORTER-STREAM but makes continue records transparent
  (let ((offset 0)
        self)
    (setq self
          (lambda (msg)
            (assert stream)
            (ecase msg
              (close (setq stream nil))
              (stream-position offset)
              (physical-stream-position (physical-stream-position stream))
              (read-octet
               (unless (< offset size)
                 (when (eql #x3c (read-ushort stream)) ;; continue record
                   (let ((n (read-ushort stream)))
                     (assert (< 0 n 8225)) ;; TODO biff8 or 2081 biff2-5
                     (incf size n)
                     (when *fHighByte*
                       (setq *fHighByte* (logand 1 (read-octet stream)))
                       (decf size)))))
               (unless (< offset size)
                 (error 'end-of-file :stream self))
               (incf offset)
               (read-octet stream)))))))

(defun biff-substream (ole-entry-stream)
  (let ((in ole-entry-stream)
        end
        eof)
    (flet ((header ()
             (let* ((h (read-BIFFRecordHeader in))
                    (nbytes (BIFFRecordHeader.length h)))
               (setq end (+ (stream-position in) nbytes))
               (values (BIFFRecordHeader.tag h)
                       (biff-continue-stream in nbytes)))))
      (assert (member (header) '(#x0009 #x0209 #x0409 #x0809))) ;; bof
      (lambda ()
        (assert (not eof))
        (stream-position in end)
        (multiple-value-bind (tag s) (header)
          (case tag ;; TODO more cell types
            (#x000a (not (setq eof t)))
            ;;(#x000b :index1)
            (#x0085 (read-BIFF-BoundSheet8 s))
            (#x00fc (let (*fHighByte*) (read-BIFF-SST s)))
            (#x00fd (read-BIFF-LabelSst s))
            ;;(#x020b (read-BIFF-Index s))
            (#x027e (read-BIFF-Rk s))
            (t tag)))))))

(defun princ-cell-value (x sst)
  (typecase x
    (BIFF-LabelSst
     (let ((c (BIFF-LabelSst.cell x)))
       `(:label ,(BIFF-Cell.rw c)
                ,(BIFF-Cell.col c)
                ,(BIFF-XLUnicodeRichExtendedString.rgb
                  (aref (BIFF-SST.rgb sst) (BIFF-LabelSst.isst x))))))
    (BIFF-RK
     `(:number ,(BIFF-RK.rw x)
               ,(BIFF-RK.col x)
               ,(BIFF-RkNumber.value (BIFF-RkRec.rk (BIFF-RK.RkRec x)))))))

(defun parse-sheet (BIFF-BoundSheet8 stream sst)
  (stream-position stream (BIFF-BoundSheet8.lbPlyPos BIFF-BoundSheet8))
  (do (z x (s (biff-substream stream)))
      ((not (setq x (funcall s)))
       (nreverse z))
    (let ((v (princ-cell-value x sst)))
      (when v
        (push v z))))
  #+nil
  (let ((index (funcall (biff-substream stream))))
    (etypecase index
      (BIFF-Index index #+nil(BIFF-Index.rgibRw )))))

(defun parse-xls-file (filename)
  (with-stream (f (ole-file-stream filename))
    (let ((e (find-ole-entry f :name "Workbook" :type 2)))
      (when e
        (with-stream (in (ole-entry-stream f e))
          (let (sheets sst)
            (do (x (globals (biff-substream in)))
                ((not (setq x (funcall globals)))
                 (setq sheets (nreverse sheets)))
              (typecase x
                (BIFF-BoundSheet8 (push x sheets))
                (BIFF-SST (setq sst x))))
            `(:workbook
              ,@(loop
                   for x in sheets
                   collect `(:sheet
                             ,(BIFF-ShortXLUnicodeString.decoded
                               (BIFF-BoundSheet8.stName x))
                             ,@(parse-sheet x in sst))))))))))
