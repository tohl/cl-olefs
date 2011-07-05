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
              (when (equal "Pictures" entry-name)
                (walk-RecordHeader-tree
                 ole-file
                 entry
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
                            (alexandria:copy-stream in out))))
                     (declare (ignore blip))
                     (format html "<p><img src=\"_~d.~(~a~)\">~%" i kind)))))))))))))

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

(define-structure PersistDirectoryEntry ()
  ;; (%dummy1 ubyte)
  ;; (%dummy2 ubyte)
  ;; (%dummy3 ubyte)
  ;; (%dummy4 ubyte)
  (%dummy dword)
  (persistId t :compute (ash %dummy -12))
  (cPersist t :compute (logand #x0fff %dummy))
  (rgPersistOffset (dword cPersist)))

(defstruct blip header ext guid guid2 metafileHeader)

(defun read-record-body (stream RecordHeader &optional fn)
  (let ((x RecordHeader #+nil(read-RecordHeader stream)))
    (with-slots (recVer recInstance recType recLen) x
      (flet ((blip (ext guid2 &optional metafileHeader)
               (with-shorter-stream (in stream (RecordHeader.recLen x))
                 (let* ((start (file-position stream))
                        (end (+ start (RecordHeader.recLen x)))
                        (y (make-blip
                            :header x
                            :ext ext
                            :guid (read-value 'guid in)
                            :guid2 (when (member recInstance guid2)
                                     (read-value 'guid in))
                            :metafileHeader (if metafileHeader
                                                (read-value 'OfficeArtMetafileHeader in)
                                                (read-value 'ubyte in)))))
                   (when fn
                     (funcall fn y in))
                   (unless (eql end (file-position stream))
                     (file-position stream end))
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
           (with-shorter-stream (in stream (RecordHeader.recLen x))
             (list x (read-UserEditAtom in))))
          (#.RT_PersistDirectoryAtom ;; TODO
           (assert (zerop recVer))
           (assert (zerop recInstance))
           (print (RecordHeader.recLen x))
           (with-shorter-stream (in stream (RecordHeader.recLen x))
             (list x
                   (read-PersistDirectoryEntry in)
                   #+nil
                   (loop
                      for fpos = 0 then (file-position in)
                      while (< fpos (RecordHeader.recLen x))
                      collect (progn
                                (print fpos)
                                (read-PersistDirectoryEntry in))))))
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
    (with-ole-entry-stream (in ole-file entry)
      (labels ((rec (level pos parents)
                 (handler-case
                     (loop
                        for i from 0
                        until (<= 1 pos (file-position in))
                        do (let* ((h (read-RecordHeader in))
                                  (start (file-position in))
                                  (end (+ start (RecordHeader.recLen h))))
                             (funcall fn in level i h start end parents)
                             (if (= #xf (RecordHeader.recVer h))
                                 (rec (1+ level)
                                      (if (plusp pos)
                                          (min pos end)
                                          end)
                                      (cons h parents))
                                 (file-position in end))
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

(define-structure OfficeArtFOPTEOPID ()
  (%dummy ushort)
  (opid t :compute (logand #x3fff %dummy))
  (fBid t :compute (if (zerop (logand #x4000 %dummy)) nil t))
  (fComplex t :compute (if (zerop (logand #x8000 %dummy)) nil t)))

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
         (declare (ignore start end))
         (when debug
           ;; pre
           (when (and (zerop level) (plusp i))
             (out "<hr/>~%"))
           ;; msg
           (when debug
             (out "<div class=\"h\">~%<pre class=\"m\">~a #x~x ~a</pre>~%"
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
            (unless (or (member #.RT_PROGTAGS parents :key 'RecordHeader.recType)
                        (member #.RT_NOTES parents :key 'RecordHeader.recType)
                        (member #.RT_MAINMASTER parents :key 'RecordHeader.recType))
              (cond
                ((member #.RT_SlideListWithText parents :key 'RecordHeader.recType)
                 (push ;; TODO also slide-no + text-no inside slide
                  (list
                   text-slide-no
                   (incf text-no)
                   (with-output-to-string (s)
                     (loop
                        for j from 0 below (RecordHeader.recLen h) by 2
                        do (format s "~a" (utf-char (read-value 'ushort in))))))
                  texts))
                (t
                 (out "<p>")
                 (loop
                    for j from 0 below (RecordHeader.recLen h) by 2
                    do (out "~a" (utf-char (read-value 'ushort in))))
                 (out "</p>~%")))))
           (#.RT_TextBytesAtom ;; ascii
            (unless (or (member #.RT_PROGTAGS parents :key 'RecordHeader.recType)
                        (member #.RT_NOTES parents :key 'RecordHeader.recType)
                        (member #.RT_MAINMASTER parents :key 'RecordHeader.recType))
              (cond
                ((member #.RT_SlideListWithText parents :key 'RecordHeader.recType)
                 (push ;; TODO also slide-no + text-no inside slide
                  (list
                   text-slide-no
                   (incf text-no)
                   (with-output-to-string (s)
                     (loop
                        for j from 0 below (RecordHeader.recLen h)
                        do (format s "~a" (ascii-char (read-byte in))))))
                  texts))
                (t
                 (out "<p>")
                 (loop
                    for j from 0 below (RecordHeader.recLen h)
                    do (out "~a" (ascii-char (read-byte in))))
                 (out "</p>~%")))))
           (#.RT_OUTLINETEXTREFATOM
            (let* ((index (1+ (read-value 'dword in)))
                   (text (caddr
                          (find-if (lambda (x)
                                     (and (= slide-no (car x))
                                          (= index (cadr x))))
                                   texts))))
              (when text
                (out "<p>~a</p>~%" text))))
           ;; TODO RT_DOCUMENT / RT_SLIDELISTWITHTEXT / RT_TEXTBYTESATOM
           (#.RT_OfficeArtFOPT
            (with-shorter-stream (s in (RecordHeader.recLen h))
              (let ((len (RecordHeader.recLen h)))
                (loop
                   while (< (file-position s) len)
                   do (let ((opid (read-OfficeArtFOPTEOPID s))
                            (value (read-value 'dword s)))
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

(defun find-ole-entry (ole-file name)
  (traverse-directories
   ole-file
   (lambda (entry id level)
     (declare (ignore id level))
     (let ((entry-name (ole-entry-name-to-string
                        (ole-entry.name entry)
                        (ole-entry.name-length entry))))
       (when (equal name entry-name)
         (return-from find-ole-entry entry))))))

(defun ppt-file-to-html-naive (filename &optional (stream *standard-output*))
  (with-ole-file (ole-file filename)
    (let ((pictures nil))
      (walk-RecordHeader-tree ole-file
                              (find-ole-entry ole-file "Pictures")
                              (lambda (in level i h start end parents)
                                (declare (ignore level end parents))
                                (multiple-value-bind (blip kind)
                                    (read-record-body in h)
                                  (declare (ignore blip))
                                  (push (list i (- start 8) kind) pictures))))
      (ppt-entry-to-html-naive ole-file
                               (find-ole-entry ole-file "PowerPoint Document")
                               stream
                               filename
                               pictures
                               nil))))

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
               do (out "~a" (utf-char (read-value 'ushort in))))
            (out "</p>~%"))
           (#.RT_TextBytesAtom ;; ascii
            (out "<p>")
            (loop
               for j from 0 below (RecordHeader.recLen h)
               do (out "~a" (ascii-char (read-byte in))))
            (out "</p>~%")))))
      (out "</div>~%</body>~%</html>~%"))))

(defun process-PersistDirectoryAtom (htab in)
  (let ((d (cadr (read-record in))))
    (with-slots (persistId cPersist rgPersistOffset) d
      (loop
         for n from 0
         for o across rgPersistOffset
         do (let ((k (+ persistId n)))
              (print (list k :-> o))
              (setf (gethash k htab) o)))))
  #+nil
  (loop
     for d = (cadr (read-record in)) ;;then (cadr (read-record in))
     do (with-slots (persistId cPersist rgPersistOffset) d
          (loop
             for n from 0
             for o across rgPersistOffset
             do (let ((k (+ persistId n)))
                  (print (list k :-> o))
                  (setf (gethash k htab) o))))))

(defun ppt-file-to-html (filename &optional (stream *standard-output*))
  (with-ole-file (ole-file filename)
    (let ((u (block CurrentUser
               (traverse-directories
                ole-file
                (lambda (entry id level)
                  (declare (ignore id level))
                  (case (ole-entry.object-type entry)
                    (2 ;; stream
                     (let ((entry-name (ole-entry-name-to-string
                                        (ole-entry.name entry)
                                        (ole-entry.name-length entry))))
                       (when (equal "Current User" entry-name)
                         (walk-RecordHeader-tree
                          ole-file
                          entry
                          (lambda (in level i h start end parents)
                            (declare (ignore level i start end parents))
                            (return-from CurrentUser
                              (cadr (read-record-body in h))))))))))))))
      (describe u)
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
                (with-ole-entry-stream (in ole-file entry)
                  (let ((htab (make-hash-table))) ;; persist oid -> fpos
                    (file-position in (CurrentUserAtom.offsetToCurrentEdit u))
                    (loop
                       for e = (cadr (read-record in)) then (cadr (read-record in))
                       do (progn
                            (describe e)
                            (file-position in (UserEditAtom.offsetPersistDirectory e))
                            (process-PersistDirectoryAtom htab in))
                       until (zerop (UserEditAtom.offsetLastEdit e))
                       do (file-position in (UserEditAtom.offsetLastEdit e))))
                  #+nil(file-position in 0)
                  #+nil(print (read-record in))))))))))))
