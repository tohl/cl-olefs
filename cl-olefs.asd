;; -*- lisp; -*-

(defpackage :cl-olefs-system
  (:use :asdf :cl))

(in-package :cl-olefs-system)

(defsystem :cl-olefs
  :description "OLE File System tools for Common Lisp."
  :version ""
  :author "Tomas Hlavaty"
  :maintainer "Tomas Hlavaty"
  :licence ""
  :depends-on (:trivial-gray-streams :alexandria)
  :serial t
  :components ((:file "package")
               (:file "cdef")
               (:file "enums")
               (:file "olefs")))
