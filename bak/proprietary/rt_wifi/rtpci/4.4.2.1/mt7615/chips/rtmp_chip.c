/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2004, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	rt_chip.c

	Abstract:
	Ralink Wireless driver CHIP related functions

	Revision History:
	Who         When          What
	--------    ----------    ----------------------------------------------
*/


#include "rt_config.h"


BOOLEAN rt28xx_eeprom_read16(RTMP_ADAPTER *pAd, USHORT offset, USHORT *value)
{
    if (pAd->chipOps.eeread) {
        return pAd->chipOps.eeread(pAd, offset, value);
    } else {
        return FALSE;
    }
}


BOOLEAN rt28xx_eeprom_read_with_range(RTMP_ADAPTER *pAd, USHORT start, USHORT length, UCHAR *pbuf)
{
    if (pAd->chipOps.eeread_range) {
        return pAd->chipOps.eeread_range(pAd, start, length, pbuf);
    } else {
        return FALSE;
    }
}
/*
========================================================================
Routine Description:
	write high memory.
	if firmware do not support auto high/low memory switching, we should switch to high memory by ourself.

Arguments:
	pAd				- WLAN control block pointer
	Offset			- Memory offsets
	Value			- Written value
	Unit				- Unit in "Byte"

Return Value:
	None

Note:
========================================================================
*/
VOID RtmpChipWriteHighMemory(
	IN RTMP_ADAPTER *pAd,
	IN USHORT Offset,
	IN UINT32 Value,
	IN UINT8 Unit)
{
#ifdef RTMP_MAC_PCI
#endif /* RTMP_MAC_PCI */
}


/*
========================================================================
Routine Description:
	write memory

Arguments:
	pAd				- WLAN control block pointer
	Offset			- Memory offsets
	Value			- Written value
	Unit				- Unit in "Byte"
Return Value:
	None

Note:
========================================================================
*/
VOID RtmpChipWriteMemory(
	IN	RTMP_ADAPTER	*pAd,
	IN	USHORT			Offset,
	IN	UINT32			Value,
	IN	UINT8			Unit)
{
	switch(Unit)
	{
		case 1:
			RTMP_IO_WRITE8(pAd, Offset, Value);
			break;
		case 2:
			RTMP_IO_WRITE16(pAd, Offset, Value);
			break;
		case 4:
			RTMP_IO_WRITE32(pAd, Offset, Value);
		default:
			break;
	}
}


/*
========================================================================
Routine Description:
	Initialize specific beacon frame architecture.

Arguments:
	pAd				- WLAN control block pointer

Return Value:
	None

Note:
========================================================================
*/
VOID RtmpChipBcnSpecInit(RTMP_ADAPTER *pAd)
{
}


/*
========================================================================
Routine Description:
	Initialize normal beacon frame architecture.

Arguments:
	pAd				- WLAN control block pointer

Return Value:
	None

Note:
========================================================================
*/
VOID RtmpChipBcnInit(
	IN RTMP_ADAPTER *pAd)
{
	RTMP_CHIP_CAP *pChipCap = &pAd->chipCap;


	pChipCap->FlgIsSupSpecBcnBuf = FALSE;
	pChipCap->BcnMaxHwNum = 8;
	pChipCap->BcnMaxNum = (pChipCap->BcnMaxHwNum - MAX_MESH_NUM - MAX_APCLI_NUM);
	pChipCap->BcnMaxHwSize = 0x1000;

	pChipCap->BcnBase[0] = 0x7800;
	pChipCap->BcnBase[1] = 0x7A00;
	pChipCap->BcnBase[2] = 0x7C00;
	pChipCap->BcnBase[3] = 0x7E00;
	pChipCap->BcnBase[4] = 0x7200;
	pChipCap->BcnBase[5] = 0x7400;
	pChipCap->BcnBase[6] = 0x5DC0;
	pChipCap->BcnBase[7] = 0x5BC0;

	/*
		If the MAX_MBSSID_NUM is larger than 6,
		it shall reserve some WCID space(wcid 222~253) for beacon frames.
		-	these wcid 238~253 are reserved for beacon#6(ra6).
		-	these wcid 222~237 are reserved for beacon#7(ra7).
	*/
	if (pChipCap->BcnMaxNum == 8)
		pChipCap->WcidHwRsvNum = 222;
	else if (pChipCap->BcnMaxNum == 7)
		pChipCap->WcidHwRsvNum = 238;
	else
		pChipCap->WcidHwRsvNum = 255;

	pAd->chipOps.BeaconUpdate = RtmpChipWriteMemory;
}





#ifdef RLT_MAC
/*
========================================================================
Routine Description:
	Initialize specific beacon frame architecture.

Arguments:
	pAd				- WLAN control block pointer

Return Value:
	None

Note:
========================================================================
*/
VOID rlt_bcn_buf_init(RTMP_ADAPTER *pAd)
{
	RTMP_CHIP_CAP *pChipCap = &pAd->chipCap;

	pChipCap->FlgIsSupSpecBcnBuf = FALSE;
	{
		pChipCap->BcnMaxHwNum = 16;
		pChipCap->WcidHwRsvNum = 255;
	}

/*
	In 16-MBSS support mode, if AP-Client is enabled,
	the last 8-MBSS would be occupied for AP-Client using.
*/
#ifdef APCLI_SUPPORT
	pChipCap->BcnMaxNum = (8 - MAX_MESH_NUM);
#else
	pChipCap->BcnMaxNum = (pChipCap->BcnMaxHwNum - MAX_MESH_NUM);
#endif /* APCLI_SUPPORT */

	pChipCap->BcnMaxHwSize = 0x2000;

	pChipCap->BcnBase[0] = 0xc000;
	pChipCap->BcnBase[1] = 0xc200;
	pChipCap->BcnBase[2] = 0xc400;
	pChipCap->BcnBase[3] = 0xc600;
	pChipCap->BcnBase[4] = 0xc800;
	pChipCap->BcnBase[5] = 0xca00;
	pChipCap->BcnBase[6] = 0xcc00;
	pChipCap->BcnBase[7] = 0xce00;
	pChipCap->BcnBase[8] = 0xd000;
	pChipCap->BcnBase[9] = 0xd200;
	pChipCap->BcnBase[10] = 0xd400;
	pChipCap->BcnBase[11] = 0xd600;
	pChipCap->BcnBase[12] = 0xd800;
	pChipCap->BcnBase[13] = 0xda00;
	pChipCap->BcnBase[14] = 0xdc00;
	pChipCap->BcnBase[15] = 0xde00;

#ifdef CONFIG_MULTI_CHANNEL
	/* Record HW Null Frame offset */
	pAd->NullBufOffset[0] = 0xd000;
	pAd->NullBufOffset[1] = 0xd200;
#endif /* CONFIG_MULTI_CHANNEL */

	pAd->chipOps.BeaconUpdate = RtmpChipWriteMemory;
}
#endif /* RLT_MAC */




#ifdef HW_ANTENNA_DIVERSITY_SUPPORT
UINT32 SetHWAntennaDivsersity(
	IN PRTMP_ADAPTER		pAd,
	IN BOOLEAN				Enable)
{
	if (Enable == TRUE)
	{
		UINT8 BBPValue = 0, RFValue = 0;
		USHORT value;

		// RF_R29 bit7:6
		RT28xx_EEPROM_READ16(pAd, EEPROM_RSSI_GAIN, value);

		RT30xxReadRFRegister(pAd, RF_R29, &RFValue);
		RFValue &= 0x3f; // clear bit7:6
		RFValue |= (value << 6);
		RT30xxWriteRFRegister(pAd, RF_R29, RFValue);

		// BBP_R47 bit7=1
		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R47, &BBPValue);
		BBPValue |= 0x80;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R47, BBPValue);

		BBPValue = 0xbe;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R150, BBPValue);
		BBPValue = 0xb0;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R151, BBPValue);
		BBPValue = 0x23;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R152, BBPValue);
		BBPValue = 0x3a;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R153, BBPValue);
		BBPValue = 0x10;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R154, BBPValue);
		BBPValue = 0x3b;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R155, BBPValue);
		BBPValue = 0x04;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R253, BBPValue);

		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("HwAnDi> Enable!\n"));
	}
	else
	{
		UINT8 BBPValue = 0;

		/*
			main antenna: BBP_R152 bit7=1
			aux antenna: BBP_R152 bit7=0
		 */
		if (pAd->FixDefaultAntenna == 0)
		{
			/* fix to main antenna */
			/* do not care BBP R153, R155, R253 */
			BBPValue = 0x3e;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R150, BBPValue);
			BBPValue = 0x30;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R151, BBPValue);
			BBPValue = 0x23;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R152, BBPValue);
			BBPValue = 0x00;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R154, BBPValue);
		}
		else
		{
			/* fix to aux antenna */
			/* do not care BBP R153, R155, R253 */
			BBPValue = 0x3e;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R150, BBPValue);
			BBPValue = 0x30;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R151, BBPValue);
			BBPValue = 0xa3;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R152, BBPValue);
			BBPValue = 0x00;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R154, BBPValue);
		}

		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("HwAnDi> Disable!\n"));
	}

	return 0;
}
#endif // HW_ANTENNA_DIVERSITY_SUPPORT //


#ifdef ANT_DIVERSITY_SUPPORT
VOID HWAntennaDiversityEnable(RTMP_ADAPTER *pAd)
{
	UINT8 *regs;
	UINT8 BBPValue = 0, RFValue = 0;





	/* BBP_R47 bit7=1 */
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R47, &BBPValue);
	BBPValue |= 0x80; /* ADC6 on */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R47, BBPValue);


	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R150, regs[0]); /* ENABLE_ANTSW_OFDM and RSSI_ANTSWT */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R151, regs[1]); /* ENABLE_ANTSW_CCK and RSSI_LNASWTH_HM */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R152, regs[2]); /* RSSI_LNASWTH_HL */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R153, regs[3]); /* RSSI_ANALOG_LOWTH */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R154, regs[4]); /* ANTSW_PWROFFSET, ANTSW_DELAYOFFSET and auto-control BBP R152[7] (RX_DEFAULT_ANT) */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R155, regs[5]); /* RSSI_OFFSET */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R253, regs[6]); /* MEASURE_RSSI_OFFSET */


	MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("HwAnDiv --> Enable!\n"));
}
#endif /* ANT_DIVERSITY_SUPPORT */


UINT8 NICGetBandSupported(RTMP_ADAPTER *pAd)
{
	if (BOARD_IS_5G_ONLY(pAd))
	{
		return RFIC_5GHZ;
	}
	else if (BOARD_IS_2G_ONLY(pAd))
	{
		return RFIC_24GHZ;
	}
	else if (RFIC_IS_5G_BAND(pAd))
	{
		return RFIC_DUAL_BAND;
	}
	else
		return RFIC_24GHZ;
}


INT WaitForAsicReady(RTMP_ADAPTER *pAd)
{
	UINT32 mac_val = 0;
#if defined(RTMP_MAC) || defined(RLT_MAC)
	UINT32 reg;
	int idx = 0;
#endif
	// TODO: shiang-7603
	if (pAd->chipCap.hif_type == HIF_MT) {
		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s(%d): Not support for HIF_MT yet!\n",
							__FUNCTION__, __LINE__));
		return TRUE;
	}

#if defined(RTMP_MAC) || defined(RLT_MAC)
	reg = MAC_CSR0;
	do
	{
		if (RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_NIC_NOT_EXIST))
			return FALSE;

		RTMP_IO_READ32(pAd, reg, &mac_val);
		if ((mac_val != 0x00) && (mac_val != 0xFFFFFFFF))
			return TRUE;

		RtmpOsMsDelay(5);
	} while (idx++ < 500);

#endif /* defined(RTMP_MAC) || defined(RLT_MAC) */

	MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_ERROR,
				("%s(0x%x):AsicNotReady!\n",
				__FUNCTION__, mac_val));

	return FALSE;
}


INT AsicGetMacVersion(RTMP_ADAPTER *pAd)
{
	UINT32 reg=0;

	// TODO: shiang-7603
	if (pAd->chipCap.hif_type == HIF_MT) {
		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("%s(%d): Not support for HIF_MT yet!\n",
							__FUNCTION__, __LINE__));
		return FALSE;
	}

#if defined(RTMP_MAC) || defined(RLT_MAC)
	reg = MAC_CSR0;

#endif /* defined(RTMP_MAC) || defined(RLT_MAC) */

	if (WaitForAsicReady(pAd) == TRUE)
	{
		RTMP_IO_READ32(pAd, reg, &pAd->MACVersion);
		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("MACVersion[Ver:Rev]=0x%08x : 0x%08x\n",
					pAd->MACVersion, pAd->ChipID));
		return TRUE;
	}
	else
	{
		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("%s() failed!\n", __FUNCTION__));
		return FALSE;
	}
}


/*
========================================================================
Routine Description:
	Initialize chip related information.

Arguments:
	pCB				- WLAN control block pointer

Return Value:
	None

Note:
========================================================================
*/
int RtmpChipOpsHook(VOID *pCB)
{
	RTMP_ADAPTER *pAd = (RTMP_ADAPTER *)pCB;
	RTMP_CHIP_CAP *pChipCap = &pAd->chipCap;
#if defined(RTMP_MAC) || defined(RLT_MAC) ||defined(RT65xx)
	UINT32 MacValue;
#endif
	int ret = 0;
	RTMP_CHIP_OP *pChipOps = &pAd->chipOps;

	/* sanity check */
	if (WaitForAsicReady(pAd) == FALSE)
		return -1;

	// TODO: shiang-7603
	if (IS_MT7603(pAd) || IS_MT7628(pAd) || IS_MT76x6(pAd) || IS_MT7637(pAd) || IS_MT7615(pAd)) {
		MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_OFF, 
                                        ("%s(%d): Not support for HIF_MT yet! MACVersion=0x%x\n",
					__FUNCTION__, __LINE__, pAd->MACVersion));
	}
	else
	{
#if defined(RTMP_MAC) || defined(RLT_MAC)
		RTMP_IO_READ32(pAd, MAC_CSR0, &MacValue);
		pAd->MACVersion = MacValue;
#endif /* defined(RTMP_MAC) || defined(RLT_MAC) */
	}

	if (pAd->MACVersion == 0xffffffff)
		return -1;


	/* default init */
	RTMP_DRS_ALG_INIT(pAd, RATE_ALG_LEGACY);


	/* EDCCA */
	pChipOps->ChipSetEDCCA= NULL;

	/*initial chip hook function*/
	WfSysPreInit(pAd);

#ifdef RTMP_MAC
	// TODO: default settings for rest of the chips!! change this to really default chip.
	RTxx_default_Init(pAd);
#endif /* RTMP_MAC */
	MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("Chip specific bbpRegTbSize=%d!\n", pChipCap->bbpRegTbSize));
	MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("Chip VCO calibration mode = %d!\n", pChipCap->FlgIsVcoReCalMode));
#ifdef DOT11W_PMF_SUPPORT
	MTWF_LOG(DBG_CAT_HW, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("[PMF] Encryption mode = %d\n", pChipCap->FlgPMFEncrtptMode));
#endif /* DOT11W_PMF_SUPPORT */

	return ret;
}


