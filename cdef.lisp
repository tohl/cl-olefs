(in-package :ole)

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
