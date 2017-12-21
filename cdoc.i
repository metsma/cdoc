/*
 * cdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

%module cdoc
%{
#include "CDOCReader.h"
#include "CDOCWriter.h"
#include "Token.h"

extern "C"
{
    SWIGEXPORT unsigned char* SWIGSTDCALL ByteVector_data(void *ptr) {
        return static_cast<std::vector<unsigned char>*>(ptr)->data();
    }
    SWIGEXPORT int SWIGSTDCALL ByteVector_size(void *ptr) {
       return static_cast<std::vector<unsigned char>*>(ptr)->size();
    }
    SWIGEXPORT void* SWIGSTDCALL ByteVector_to(unsigned char *data, int size) {
       return new std::vector<unsigned char>(data, data + size);
    }
}
%}

%pragma(csharp) imclasscode=%{
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_data")]
  public static extern global::System.IntPtr ByteVector_data(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_size")]
  public static extern int ByteVector_size(global::System.IntPtr data);
  [global::System.Runtime.InteropServices.DllImport("$dllimport", EntryPoint="ByteVector_to")]
  public static extern global::System.IntPtr ByteVector_to(
    [global::System.Runtime.InteropServices.MarshalAs(global::System.Runtime.InteropServices.UnmanagedType.LPArray)]byte[] data, int size);
%}

%typemap(cstype) std::vector<unsigned char> "byte[]"
%typemap(csin,
		 pre= "	global::System.IntPtr cPtr$csinput = (global::System.IntPtr)digidocPINVOKE.ByteVector_to($csinput, $csinput.Length);
	global::System.Runtime.InteropServices.HandleRef handleRef$csinput = new global::System.Runtime.InteropServices.HandleRef(this, cPtr$csinput);"
) std::vector<unsigned char> "handleRef$csinput"
%typemap(csout, excode=SWIGEXCODE) std::vector<unsigned char> {
  global::System.IntPtr data = $imcall;$excode
  byte[] result = new byte[$modulePINVOKE.ByteVector_size(data)];
  global::System.Runtime.InteropServices.Marshal.Copy($modulePINVOKE.ByteVector_data(data), result, 0, result.Length);
  return result;
}

%apply std::vector<unsigned char> { const std::vector<unsigned char> & };

#define CDOC_EXPORT
%include "std_string.i"
%include "CDOCReader.h"
%include "CDOCWriter.h"
%include "Token.h"
