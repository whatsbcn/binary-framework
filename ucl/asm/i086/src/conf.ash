;  conf.ash -- assembler stuff
;
;  This file is part of the UCL data compression library.
;
;  Copyright (C) 1996-2004 Markus Franz Xaver Johannes Oberhumer
;  All Rights Reserved.
;
;  The UCL library is free software; you can redistribute it and/or
;  modify it under the terms of the GNU General Public License as
;  published by the Free Software Foundation; either version 2 of
;  the License, or (at your option) any later version.
;
;  The UCL library is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with the UCL library; see the file COPYING.
;  If not, write to the Free Software Foundation, Inc.,
;  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;
;  Markus F.X.J. Oberhumer
;  <markus@oberhumer.com>
;  http://www.oberhumer.com/opensource/ucl/
;


; /***********************************************************************
; //
; ************************************************************************/

                BITS    16

%macro .text 0
                SEGMENT _TEXT class=CODE public use16 align=1
%endmacro


%macro CGLOBALF 1
                GLOBAL _%1
    %define %1 _%1
%endmacro


%macro UCL_PUBLIC 1
                CGLOBALF %1
  %ifdef __UCL_DB__
                db      0,0,0,0,0,0,0
                db      'UCL_START'
  %endif
%1:
%endmacro


%macro UCL_PUBLIC_END 1
  %ifdef __UCL_DB__
                db      'UCL_END'
  %endif
%endmacro


; vi:ts=8:et

