;; -*- lisp; -*-

(defpackage :ole-system
  (:use :asdf :cl))

(in-package :ole-system)

(defsystem :ole
  :description "Ole for Common Lisp."
  :version ""
  :author "Tomas Hlavaty"
  :maintainer "Tomas Hlavaty"
  :licence ""
  :depends-on (:trivial-gray-streams :alexandria)
  :serial t
  :components ((:file "ole")))
