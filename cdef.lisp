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

(defun slot-type-definition-for-reader (type)
  (if (atom type)
      `(',type)
      (destructuring-bind (type1 size) type
        (if (numberp size)
            `('(,type1 ,size))
            `((list ',type1 ,size))))))

(defun slot-reader-let-definition (name type &key compute always member)
  (list
   name
   (flet ((value ()
            (cond
              (compute compute)
              (t `(read-value ,@(slot-type-definition-for-reader type) stream)))))
     (cond
       (always `(let ((x ,(value))) (assert (equal x ,always)) x))
       (member `(let ((x ,(value))) (assert (member x ,member)) x))
       (t (value))))))

(defmacro define-structure (name options &rest slots)
  (declare (ignore options))
  `(progn
     (defstruct (,name (:conc-name ,(intern (format nil "~a." name))))
       ,@(loop
            for slot in slots
            collect (list (car slot)
                          nil
                          :type (slot-type-definition (cadr slot)))))
     (defun ,(intern (format nil "READ-~a" name)) (stream)
       (let* (,@(loop
                   for slot in slots
                   collect (apply 'slot-reader-let-definition slot)))
         (,(intern (format nil "MAKE-~a" name))
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
