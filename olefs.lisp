(in-package :olefs)

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

(defun read-value (type stream)
  (if (atom type)
      (ecase type
        (ubyte (read-byte stream))
        (achar (read-byte stream))
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
             (unless (member x (list +difsect+ +fatsect+ +endofchain+ +freesect+))
               (assert (and #+nil(< +unused-sector+ x) (<= 0 x +maxregsect+)))
               (cons x (rec (aref fat x))))))
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
      ;;(describe ole-file)
      (check-ole-header (ole-file.header ole-file))
      ;;(describe header)
      ;;(terpri)
      #+nil
      (traverse-directories ole-file
                            (lambda (entry id level)
                              (declare (ignore id))
                              (dotimes (i level)
                                (write-string "   "))
                              (print-ole-entry entry *standard-output*)
                              (terpri)))
      (funcall fn ole-file))))

(defmacro with-ole-file ((ole-file filename) &body body)
  `(call-with-ole-file ,filename (lambda (,ole-file) ,@body)))

(defclass ole-entry-stream (trivial-gray-streams:fundamental-binary-input-stream
                            trivial-gray-streams:trivial-gray-stream-mixin)
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
      (setq chain (let ((x (sector-chain
                            (ole-file.fat ole-file)
                            (ole-entry.starting-sector-location
                             (if mini
                                 (aref (ole-file.directories ole-file) 0)
                                 ole-entry)))))
                    (when x
                      (coerce x 'vector)))
            mchain (when mini
                     (let ((x (sector-chain
                               (ole-file.mfat ole-file)
                               (ole-entry.starting-sector-location ole-entry))))
                       (when x
                         (coerce x 'vector))))
            size (ole-entry.stream-size ole-entry)))))

(defmethod trivial-gray-streams::stream-element-type ((stream ole-entry-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-file-position ((stream ole-entry-stream))
  (with-slots (offset) stream
    offset))

(defmethod (setf trivial-gray-streams:stream-file-position) (x (stream ole-entry-stream))
  (with-slots (offset sector) stream
    (setf offset x
          sector nil)))

(defmethod trivial-gray-streams:stream-read-byte ((stream ole-entry-stream))
  (with-slots (ole-file ole-entry offset chain mchain sector buffer size) stream
    (assert (not (minusp offset)))
    (if (< offset size)
        (flet ((pick (q i)
                 (unless (eql sector q)
                   (let ((ole-stream (ole-file.stream ole-file)))
                     (seek-sector (aref chain q) ole-stream)
                     (let ((n (read-sequence buffer ole-stream)))
                       (assert (eql 512 n))))
                   (setq sector q))
                 (prog1 (aref buffer i)
                   (incf offset))))
          (if mchain
              (multiple-value-bind (mq mr) (floor offset 64)
                (multiple-value-bind (q r) (floor (aref mchain mq) (/ 512 64))
                  (pick q (+ (* r 64) mr))))
              (multiple-value-bind (q r) (floor offset 512)
                (pick q r))))
        :eof)))

(defun call-with-ole-entry-stream (stream fn)
  (with-open-stream (x stream)
    (funcall fn x)))

(defmacro with-ole-entry-stream ((var ole-file ole-entry) &body body)
  `(call-with-ole-entry-stream
    (make-instance 'ole-entry-stream :ole-file ,ole-file :ole-entry ,ole-entry)
    (lambda (,var) ,@body)))

(defun extract-ole-file (filename &optional (dir "/tmp"))
  (with-ole-file (ole-file filename)
    (with-open-file (html (format nil "~a/index.html" dir)
                          :direction :output
                          :if-does-not-exist :create
                          :if-exists :supersede
                          :element-type 'character)
      (traverse-directories
       ole-file
       (lambda (entry id level)
         (declare (ignore id level))
         (case (ole-entry.object-type entry)
           (2 ;; stream
            (let ((entry-name (ole-entry-name-to-string
                               (ole-entry.name entry)
                               (ole-entry.name-length entry))))
              (with-ole-entry-stream (in ole-file entry)
                (with-open-file (out (format nil "~a/~a" dir entry-name)
                                     :direction :output
                                     :if-does-not-exist :create
                                     :if-exists :supersede
                                     :element-type '(unsigned-byte 8))
                  (alexandria:copy-stream in out)))
              #+nil
              (when (equal "Current User" entry-name)
                (with-ole-entry-stream (in ole-file entry)
                  (print (read-record dir in))))
              (when (equal "Pictures" entry-name)
                (with-ole-entry-stream (in ole-file entry)
                  (loop
                     for n from 1
                     while t ;; TODO until eof!
                     do (multiple-value-bind (blib kind)
                            (read-record in dir n)
                          (declare (ignore blib))
                          (format html "<p><img src=\"_~d.~(~a~)\">~%" n kind)))))))))))))

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

(defclass shorter-stream (trivial-gray-streams:fundamental-binary-input-stream
                          trivial-gray-streams:trivial-gray-stream-mixin)
  ((wrap :initarg :wrap)
   (size :initarg :size)
   (offset :initform 0)))

(defmethod trivial-gray-streams::stream-element-type ((stream shorter-stream))
  '(unsigned-byte 8))

(defmethod trivial-gray-streams:stream-file-position ((stream shorter-stream))
  (with-slots (offset) stream
    offset))

(defmethod trivial-gray-streams:stream-read-byte ((stream shorter-stream))
  (with-slots (wrap size offset) stream
    (cond
      ((< offset size)
       (incf offset)
       (read-byte wrap))
      (t :eof))))

(defun call-with-shorter-stream (stream fn)
  (with-open-stream (x stream)
    (funcall fn x)))

(defmacro with-shorter-stream ((var wrap size) &body body)
  `(call-with-shorter-stream
    (make-instance 'shorter-stream :wrap ,wrap :size ,size)
    (lambda (,var) ,@body)))

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

(defun read-record (stream dir &optional n) ;; TODO remove dir and n
  (let ((x (read-RecordHeader stream)))
    (with-slots (recVer recInstance recType recLen) x
      (flet ((blip (ext guid2 &optional metafileHeader)
               (with-shorter-stream (in stream (RecordHeader.recLen x))
                 (list x ;; TODO make struct
                       (read-value 'guid in)
                       (when (member recInstance guid2)
                         (read-value 'guid in))
                       (if metafileHeader
                           (read-value 'OfficeArtMetafileHeader in)
                           (read-value 'ubyte in))
                       (with-open-file (out (format nil "~a/_~d.~a" dir n ext)
                                            :direction :output
                                            :if-does-not-exist :create
                                            :if-exists :supersede
                                            :element-type '(unsigned-byte 8))
                         (alexandria:copy-stream in out))))))
        (ecase recType
          (#.RT_CurrentUserAtom
           (assert (zerop recVer))
           (assert (zerop recInstance))
           (list x (read-CurrentUserAtom stream))
           #+nil ;; why recLen too small?
           (with-shorter-stream (in stream (RecordHeader.recLen x))
             (list x (read-CurrentUserAtom in))))
          ((#xF01A) ;; OfficeArtBlipEMF
           (assert (zerop recVer))
           (assert (member recInstance '(#x3d4 #x3d5)))
           (values (blip "emf" '(#x3d5) t) :emf))
          ((#xF01B) ;; OfficeArtBlipWMF
           (assert (zerop recVer))
           (assert (member recInstance '(#x216 #x217)))
           (values (blip "wmf" '(#x217) t) :wmf))
          ((#xF01C) ;; OfficeArtBlipPICT
           (assert (zerop recVer))
           (assert (member recInstance '(#x542 #x543)))
           (values (blip "pict" '(#x543) t) :pict))
          (#xF01D ;; OfficeArtBlipJPEG
           (assert (zerop recVer))
           (assert (member recInstance '(#x46A #x46B #x6E2 #x6E3)))
           (values (blip "jpeg" '(#x46B #x6E3)) :jpeg))
          ((#xF01E) ;; OfficeArtBlipPNG
           (assert (zerop recVer))
           (assert (member recInstance '(#x6e0 #x6e1)))
           (values (blip "png"'(#x6e1)) :png))
          ((#xF01F) ;; OfficeArtBlipDIB
           (assert (zerop recVer))
           (assert (member recInstance '(#x7a8 #x7a9)))
           (values (blip "dib" '(#x7a9)) :dib))
          ((#xF029) ;; OfficeArtBlipTIFF
           (assert (zerop recVer))
           (assert (member recInstance '(#x6e4 #x6e5)))
           (values (blip "tiff" '(#x6e5)) :tiff))
          ((#xF02A) ;; OfficeArtBlipJPEG
           (assert (zerop recVer))
           (assert (member recInstance '(#x46A #x46B #x6E2 #x6E3)))
           (values (blip "jpeg" '(#x46B #x6E3)) :jpeg)))))))

(defun walk-RecordHeader-tree (ole-file entry fn)
  (with-ole-entry-stream (in ole-file entry)
    (labels ((rec (level pos)
               (handler-case
                   (loop
                      for i from 0
                      until (<= 1 pos (file-position in))
                      do (let* ((h (read-RecordHeader in))
                                (start (file-position in))
                                (end (+ start (RecordHeader.recLen h))))
                           (funcall fn in level i h start end)
                           (if (= #xf (RecordHeader.recVer h))
                               (rec (1+ level)
                                    (if (plusp pos)
                                        (min pos end)
                                        end))
                               (file-position in end))))
                 (end-of-file ()
                   (assert (zerop level))))))
      (rec 0 0))))

(defun print-RecordHeader-tree (ole-file entry)
  (walk-RecordHeader-tree
   ole-file
   entry
   (lambda (in level i h start end)
     (declare (ignore in))
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
  (with-ole-file (ole-file filename)
    (traverse-directories
     ole-file
     (lambda (entry id level)
       (declare (ignore id level))
       (case (ole-entry.object-type entry)
         (2 ;; stream
          (let ((entry-name (ole-entry-name-to-string
                             (ole-entry.name entry)
                             (ole-entry.name-length entry))))
            (when (equal "PowerPoint Document" entry-name)
              (print-RecordHeader-tree ole-file entry)))))))))

(defun utf-char (n)                ;; TODO utf properly
  (if (member n '(#x0a #x0b #x0d)) ;; #x0b = vertical tab
      "<br/>"
      (code-char n)))

(defun ascii-char (n)
  (if (member n '(#x0a #x0b #x0d)) ;; #x0b = vertical tab
      "<br/>"
      (code-char n)))

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
       (lambda (in level i h start end)
         (declare (ignore i level start end))
         (case (RecordHeader.recType h)
           ((#x0fa0  ;; RT_TextCharsAtom utf16le
             #x0fba) ;; RT_CString
            (out "<p>")
            (loop
               for j from 0 below (RecordHeader.recLen h) by 2
               do (out "~a" (utf-char (read-value 'ushort in))))
            (out "</p>~%"))
           (#x0fa8 ;; RT_TextBytesAtom ascii
            (out "<p>")
            (loop
               for j from 0 below (RecordHeader.recLen h)
               do (out "~a" (ascii-char (read-byte in))))
            (out "</p>~%"))
           ((#x03ee  ;; RT_Slide
             #x03e8) ;; RT_Document
            (when (plusp slide-no)
              (out "<hr/>~%</div>~%"))
            (out "<div class=\"slide\">~%<h1>Slide ~d</h1>~%" (incf slide-no))))))
      (when (plusp slide-no)
        (out "</div>~%"))
      (out "</body>~%</html>~%"))))

(defun ppt-file-to-html (filename &optional (stream *standard-output*))
  (with-ole-file (ole-file filename)
    (traverse-directories
     ole-file
     (lambda (entry id level)
       (declare (ignore id level))
       (case (ole-entry.object-type entry)
         (2 ;; stream
          (let ((entry-name (ole-entry-name-to-string
                             (ole-entry.name entry)
                             (ole-entry.name-length entry))))
            (when (equal "PowerPoint Document" entry-name)
              (ppt-entry-to-html ole-file entry stream filename)))))))))
