;;; Copyright (C) 2011, 2012, 2013 Tomas Hlavaty <tom@logand.com>
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

(deftype achar () '(unsigned-byte 8))
(deftype ubyte () '(unsigned-byte 8))
(deftype ushort () '(unsigned-byte 16))
(deftype wchar () '(unsigned-byte 16))
(deftype dword () '(unsigned-byte 32))
(deftype ulonglong () '(unsigned-byte 64))
(deftype filetime () '(unsigned-byte 64))
(deftype guid () '(vector ubyte 16))

(defun slot-type-definition (type)
  (if (atom type)
      type
      (destructuring-bind (type1 size) type
        (list 'vector type1 (if (numberp size) size '*)))))

(defun slot-type-read (type)
  (cond
    ((eq 'ubyte type)
     `(read-octet stream))
    ((atom type)
     `(,(intern (format nil "READ-~a" type)) stream))
    ((eq 'ubyte (car type))
     `(read-octets stream ,(cadr type)))
    (t
     `(read-vector stream ,(cadr type) ',(car type)
                   ',(intern (format nil "READ-~a" (car type)))))))

;;(slot-type-read #+nil 'dword #+nil '(byte 6) '(wchar 6))

(defun slot-reader-let-definition (name type &key compute always member)
  (list
   name
   (flet ((value ()
            (cond
              (compute compute)
              (t (slot-type-read type)))))
     (cond
       (always `(let ((x ,(value))) (assert (equal x ,always)) x))
       (member `(let ((x ,(value))) (assert (member x ,member)) x))
       (t (value))))))

(defmacro define-structure (name options &rest slots)
  (declare (ignore options))
  `(progn
     (defstruct (,name (:conc-name ,(intern (format nil "~a." name))))
       %physical-stream-position
       ,@(loop
            for slot in slots
            collect (list (car slot)
                          nil
                          :type (slot-type-definition (cadr slot)))))
     (defun ,(intern (format nil "READ-~a" name)) (stream)
       (let* ((%physical-stream-position (physical-stream-position stream))
              ,@(loop
                   for slot in slots
                   collect (apply 'slot-reader-let-definition slot)))
         (,(intern (format nil "MAKE-~a" name))
           :%physical-stream-position %physical-stream-position
           ,@(loop
                for slot in slots
                appending (list
                           (intern (symbol-name (car slot)) :keyword)
                           (car slot))))))))

(defgeneric enum-by-key (name key))
(defgeneric enum-by-value (name value))

(defmacro defenum (name args &rest values)
  (declare (ignore args))
  `(progn
     (defmethod enum-by-key ((name (eql ',name)) key)
       (cdr (assoc key ',(loop
                            for (k v) in values
                            collect (cons k v)))))
     (defmethod enum-by-value ((name (eql ',name)) value)
       (cdr (assoc value ',(loop
                              for (k v) in values
                              collect (cons v k)))))
     ,@(loop
          for (k v) in values
          collect `(defconstant ,k ,v))))

;;(enum-by-key 'RecordType 'RT_DocumentAtom)
;;(enum-by-value 'RecordType #x03E9)
