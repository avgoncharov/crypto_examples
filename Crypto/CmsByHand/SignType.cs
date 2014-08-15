using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CmsByHand
{
	private enum SignType
	{
		Pkcs7,
		CAdES_BES,
		CAdES_T,
		CAdES_A,
		CAdES_C,
		CAdES_EPES,
		CAdES_X_1,
		CAdES_X_2,
		CAdES_X_L,

		PDF,
		PAdES_BES,
		PAdES_T,
		PAdES_A,
		PAdES_C,
		PAdES_EPES,
		PAdES_X_1,
		PAdES_X_2,
		PAdES_X_L,

		XMLDSIG,
		XAdES_BES,
		XAdES_T,
		XAdES_C,
		XAdES_X_1,
		XAdES_X_2,
		XAdES_X_L,
		XAdES_A
	}
}
