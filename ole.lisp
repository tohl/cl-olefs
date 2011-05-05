(defpackage :ole
  (:use :cl))

(in-package :ole)

(defconstant +maxregsect+ #xfffffffa)
(defconstant +difsect+ #xfffffffc)
(defconstant +fatsect+ #xfffffffd)
(defconstant +endofchain+ #xfffffffe)
(defconstant +freesect #xffffffff)

(defconstant +maxregsig+ #xfffffffa)
(defconstant +nostream+ #xffffffff)

(deftype ubyte () '(unsigned-byte 8))
(deftype ushort () '(unsigned-byte 16))
(deftype wchar () '(unsigned-byte 16))
(deftype dword () '(unsigned-byte 32))
(deftype ulonglong () '(unsigned-byte 64))
(deftype filetime () '(unsigned-byte 64))
(deftype guid () '(vector ubyte 16))

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

(defun print-ole-entry (ole-entry stream)
  (print-unreadable-object (ole-entry stream :type t :identity t)
    (format stream "~s ~s ~a ~sB @~s"
            (coerce
             (mapcar #'code-char
                     (coerce (subseq (ole-entry.name ole-entry)
                                     0
                                     (1- (/ (ole-entry.name-length ole-entry) 2)))
                             'list))
             'string)
            (ecase (ole-entry.object-type ole-entry)
              (0 :unknown-or-unallocated) ;; unknown
              (1 :storage-object) ;; directory
              (2 :stream-object) ;; file
              (5 :root-storage-object)) ;; root
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

(defun seek-sector-entry (ole-file location id)
  (assert (<= 0 id 3))
  (assert (file-position (ole-file.stream ole-file)
                         (+ (location-position location) (* (/ 512 4) id)))))

(defun check-ole-header (x)
  (assert (equalp #(#xd0 #xcf #x11 #xe0 #xa1 #xb1 #x1a #xe1) (ole-header.signature x)))
  (assert (equalp clsid-null (ole-header.clsid x)))
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
  #+nil(assert (eql #xfffffffe (first-difat-sector-location x)))
  #+nil(assert (eql 0 (number-of-difat-sectors x))))

(defstruct (ole-file (:conc-name ole-file.)) filename stream header bat-sectors bat)

(defun call-with-ole-file (filename fn)
  (with-open-file (stream filename :element-type '(unsigned-byte 8))
    (let* ((header (read-ole-header stream))
           (bat-sectors (loop
                           for i from 0 below (ole-header.number-of-fat-sectors header)
                           collect (read-value 'dword stream)))
           (bat (let ((x (make-array (* 512 (ole-header.number-of-fat-sectors header))
                                     :element-type 'dword)))
                  x))
           (ole-file (make-ole-file
                      :filename filename
                      :stream stream
                      :header header
                      :bat-sectors bat-sectors
                      :bat bat)))
      (check-ole-header (ole-file.header ole-file))
      (loop ;; read bat
         for location in (ole-file.bat-sectors ole-file)
         for n = -1
         do (progn
              (seek-sector location (ole-file.stream ole-file))
              (dotimes (i (/ 512 4))
                (setf (aref (ole-file.bat ole-file) (incf n))
                      (read-value 'dword (ole-file.stream ole-file))))))
      (funcall fn ole-file))))

(defmacro with-ole-file ((ole-file filename) &body body)
  `(call-with-ole-file ,filename (lambda (,ole-file) ,@body)))

(defun ls-ole (filename)
  (with-ole-file (ole-file filename)
    (let ((stream (ole-file.stream ole-file)))
      (labels ((indent (n)
                 (dotimes (i n)
                   (write-string "   ")))
               (rec (location id level)
                 ;;(seek-sector location stream)
                 (seek-sector-entry ole-file location id)
                 (let ((x (read-ole-entry stream)))
                   (indent level)
                   (print id)
                   (print-ole-entry x *standard-output*)
                   #+nil
                   (let ((y x))
                     (loop
                        for id = (ole-entry.left-sibling-id y) then (ole-entry.left-sibling-id y)
                        while (<= id +maxregsig+)
                        do (rec location id level)
                          #+nil(progn
                                 (seek-sector-entry location 128 id s)
                                 (setq y (read-structure 'directory-entry s))
                                 (format t "L~s:~s ~s~%" level id y))))
                   (let ((id (ole-entry.child-id x)))
                     (when (<= id +maxregsig+)
                       ;;(seek-sector-entry ole-file location id)
                       (rec location id (1+ level))))
                   #+nil
                   (let ((y x))
                     (loop
                        for id = (ole-entry.right-sibling-id y) then (ole-entry.right-sibling-id y)
                        while (<= id +maxregsig+)
                        do (rec location id level)
                          #+nil(progn
                                 (seek-sector-entry location 128 id s)
                                 (setq y (read-structure 'directory-entry s))
                                 (format t "R~s:~s ~s~%" level id y)))))))
        (rec (ole-header.first-directory-sector-location (ole-file.header ole-file))
             0
             0)))))
