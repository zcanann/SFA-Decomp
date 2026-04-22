#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msghndlr.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/nubevent.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msgbuf.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msg.h"
#include "TRK_MINNOW_DOLPHIN/Os/dolphin/targcont.h"
#include "TRK_MINNOW_DOLPHIN/ppc/Generic/targimpl.h"
#include "PowerPC_EABI_Support/MetroTRK/trk.h"

BOOL IsTRKConnected;

extern void* jumptable_80332F34[];

BOOL GetTRKConnected()
{
	return IsTRKConnected;
}

void SetTRKConnected(BOOL connected)
{
	IsTRKConnected = connected;
}

static void TRKMessageIntoReply(TRKBuffer* buffer, u8 ackCmd,
                                DSReplyError errSentInAck)
{
	TRKResetBuffer(buffer, 1);

	TRKAppendBuffer1_ui8(buffer, ackCmd);
	TRKAppendBuffer1_ui8(buffer, errSentInAck);
}

DSError TRKSendACK(TRKBuffer* buffer)
{
	DSError err;
	int ackTries;

	ackTries = 3;
	do {
		err = TRKMessageSend((TRK_Msg*)buffer);
		--ackTries;
	} while (err != DS_NoError && ackTries > 0);

	return err;
}

DSError TRKStandardACK(TRKBuffer* buffer, MessageCommandID commandID,
                       DSReplyError replyError)
{
	TRKMessageIntoReply(buffer, commandID, replyError);
	return TRKSendACK(buffer);
}

DSError TRKDoUnsupported(TRKBuffer* buffer)
{
	return TRKStandardACK(buffer, DSMSG_ReplyACK,
	                      DSREPLY_UnsupportedCommandError);
}

DSError TRKDoConnect(TRKBuffer* buffer)
{
	SetTRKConnected(TRUE);
	return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
}

asm DSError TRKDoDisconnect(TRKBuffer* buffer)
{
	nofralloc
	stwu r1, -0x30(r1)
	mflr r0
	lis r4, IsTRKConnected@ha
	stw r0, 0x34(r1)
	li r0, 0x0
	stw r31, 0x2c(r1)
	mr r31, r3
	stw r30, 0x28(r1)
	stw r29, 0x24(r1)
	stw r0, IsTRKConnected@l(r4)
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _dd_1
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_dd_1:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _dd_2
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x0
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_dd_2:
	li r30, 0x3
_dd_3:
	mr r3, r31
	bl TRKMessageSend
	mr. r29, r3
	subi r30, r30, 0x1
	beq _dd_4
	cmpwi r30, 0x0
	bgt _dd_3
_dd_4:
	cmpwi r29, 0x0
	bne _dd_5
	addi r3, r1, 0x8
	li r4, 0x1
	bl TRKConstructEvent
	addi r3, r1, 0x8
	bl TRKPostEvent
_dd_5:
	lwz r0, 0x34(r1)
	mr r3, r29
	lwz r31, 0x2c(r1)
	lwz r30, 0x28(r1)
	lwz r29, 0x24(r1)
	mtlr r0
	addi r1, r1, 0x30
	blr
}

DSError TRKDoReset(TRKBuffer* buffer)
{
	TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
	__TRK_reset();
	return DS_NoError;
}

DSError TRKDoVersions(TRKBuffer* buffer)
{
	DSError error;
	DSVersions versions;

	if (buffer->length != 1) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
	} else {
		TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
		error = TRKTargetVersions(&versions);

		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui8(buffer, versions.kernelMajor);
		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui8(buffer, versions.kernelMinor);
		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui8(buffer, versions.protocolMajor);
		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui8(buffer, versions.protocolMinor);

		if (error != DS_NoError)
			error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
		else
			error = TRKSendACK(buffer);
	}
}

DSError TRKDoSupportMask(TRKBuffer* buffer)
{
	DSError error;
	u8 mask[32];

	if (buffer->length != 1) {
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
	} else {
		TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
		error = TRKTargetSupportMask(mask);

		if (error == DS_NoError)
			error = TRKAppendBuffer(buffer, mask, 32);
		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui8(buffer, 2);

		if (error != DS_NoError)
			TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
		else
			TRKSendACK(buffer);
	}
}

DSError TRKDoCPUType(TRKBuffer* buffer)
{
	DSError error;
	DSCPUType cputype;

	if (buffer->length != 1) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return;
	}

	TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);

	error = TRKTargetCPUType(&cputype);

	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.cpuMajor);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.cpuMinor);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.bigEndian);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.defaultTypeSize);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.fpTypeSize);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.extended1TypeSize);
	if (error == DS_NoError)
		error = TRKAppendBuffer1_ui8(buffer, cputype.extended2TypeSize);

	if (error != DS_NoError)
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
	else
		error = TRKSendACK(buffer);
}

asm DSError TRKDoReadMemory(TRKBuffer* buffer)
{
	nofralloc
	stwu r1, -0x820(r1)
	mflr r0
	stw r0, 0x824(r1)
	stw r31, 0x81c(r1)
	mr r31, r3
	stw r30, 0x818(r1)
	lwz r0, 0x8(r3)
	cmplwi r0, 0x8
	beq _drm_3
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_0
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_0:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_1
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x2
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_1:
	li r30, 0x3
_drm_2:
	mr r3, r31
	bl TRKMessageSend
	cmpwi r3, 0x0
	subi r30, r30, 0x1
	beq _drm_31
	cmpwi r30, 0x0
	bgt _drm_2
	b _drm_31
_drm_3:
	li r4, 0x0
	bl TRKSetBufferPosition
	mr r3, r31
	addi r4, r1, 0x9
	bl TRKReadBuffer1_ui8
	mr. r30, r3
	bne _drm_4
	mr r3, r31
	addi r4, r1, 0x8
	bl TRKReadBuffer1_ui8
	mr r30, r3
_drm_4:
	cmpwi r30, 0x0
	bne _drm_5
	mr r3, r31
	addi r4, r1, 0xa
	bl TRKReadBuffer1_ui16
	mr r30, r3
_drm_5:
	cmpwi r30, 0x0
	bne _drm_6
	mr r3, r31
	addi r4, r1, 0x10
	bl TRKReadBuffer1_ui32
	mr r30, r3
_drm_6:
	lbz r0, 0x8(r1)
	rlwinm. r0, r0, 0, 30, 30
	beq _drm_10
	mr r3, r31
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_7
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_7:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_8
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x12
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_8:
	li r30, 0x3
_drm_9:
	mr r3, r31
	bl TRKMessageSend
	cmpwi r3, 0x0
	subi r30, r30, 0x1
	beq _drm_31
	cmpwi r30, 0x0
	bgt _drm_9
	b _drm_31
_drm_10:
	lhz r0, 0xa(r1)
	cmplwi r0, 0x800
	ble _drm_14
	mr r3, r31
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_11
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_11:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_12
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x11
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_12:
	li r30, 0x3
_drm_13:
	mr r3, r31
	bl TRKMessageSend
	cmpwi r3, 0x0
	subi r30, r30, 0x1
	beq _drm_31
	cmpwi r30, 0x0
	bgt _drm_13
	b _drm_31
_drm_14:
	mr r3, r31
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_15
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_15:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_16
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x0
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_16:
	cmpwi r30, 0x0
	bne _drm_18
	lbz r0, 0x8(r1)
	addi r3, r1, 0x14
	lhz r6, 0xa(r1)
	addi r5, r1, 0xc
	extrwi r0, r0, 1, 28
	lwz r4, 0x10(r1)
	stw r6, 0xc(r1)
	xori r6, r0, 0x1
	li r7, 0x1
	bl TRKTargetAccessMemory
	lwz r0, 0xc(r1)
	mr. r30, r3
	sth r0, 0xa(r1)
	bne _drm_17
	lhz r4, 0xa(r1)
	mr r3, r31
	bl TRKAppendBuffer1_ui16
	mr r30, r3
_drm_17:
	cmpwi r30, 0x0
	bne _drm_18
	lwz r5, 0xc(r1)
	mr r3, r31
	addi r4, r1, 0x14
	bl TRKAppendBuffer
	mr r30, r3
_drm_18:
	cmpwi r30, 0x0
	beq _drm_29
	subi r0, r30, 0x700
	cmplwi r0, 0x6
	bgt _drm_24
	lis r3, jumptable_80332F34@ha
	slwi r0, r0, 2
	addi r3, r3, jumptable_80332F34@l
	lwzx r0, r3, r0
	mtctr r0
	bctr
_drm_19:
	li r30, 0x15
	b _drm_25
_drm_20:
	li r30, 0x13
	b _drm_25
_drm_21:
	li r30, 0x21
	b _drm_25
_drm_22:
	li r30, 0x22
	b _drm_25
_drm_23:
	li r30, 0x20
	b _drm_25
_drm_24:
	li r30, 0x3
_drm_25:
	mr r3, r31
	li r4, 0x1
	bl TRKResetBuffer
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_26
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	li r0, 0x80
	stb r0, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_26:
	lwz r3, 0xc(r31)
	cmplwi r3, 0x880
	bge _drm_27
	addi r0, r3, 0x1
	add r3, r31, r3
	stw r0, 0xc(r31)
	stb r30, 0x10(r3)
	lwz r3, 0x8(r31)
	addi r0, r3, 0x1
	stw r0, 0x8(r31)
_drm_27:
	li r30, 0x3
_drm_28:
	mr r3, r31
	bl TRKMessageSend
	cmpwi r3, 0x0
	subi r30, r30, 0x1
	beq _drm_31
	cmpwi r30, 0x0
	bgt _drm_28
	b _drm_31
_drm_29:
	li r30, 0x3
_drm_30:
	mr r3, r31
	bl TRKMessageSend
	cmpwi r3, 0x0
	subi r30, r30, 0x1
	beq _drm_31
	cmpwi r30, 0x0
	bgt _drm_30
_drm_31:
	lwz r0, 0x824(r1)
	lwz r31, 0x81c(r1)
	lwz r30, 0x818(r1)
	mtlr r0
	addi r1, r1, 0x820
	blr
}

DSError TRKDoWriteMemory(TRKBuffer* buffer)
{
	DSError error;
	DSReplyError replyError;
	u8 tmpBuffer[0x800];
	u32 msg_start;
	u32 length;
	u16 msg_length;
	u8 msg_command;
	u8 msg_options;

	if (buffer->length <= 8) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return error;
	}

	TRKSetBufferPosition(buffer, DSREPLY_NoError);
	error = TRKReadBuffer1_ui8(buffer, &msg_command);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui8(buffer, &msg_options);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui16(buffer, &msg_length);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui32(buffer, &msg_start);

	if (msg_options & 2) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK,
		                       DSREPLY_UnsupportedOptionError);
		return error;
	}

	if ((buffer->length != msg_length + 8) || (msg_length > 0x800)) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_ParameterError);
	} else {
		if (error == DS_NoError) {
			length = (u32)msg_length;
			error  = TRKReadBuffer(buffer, tmpBuffer, length);
			if (error == DS_NoError) {
				error = TRKTargetAccessMemory(tmpBuffer, msg_start, &length,
				                              (msg_options & 8)
				                                  ? MEMACCESS_UserMemory
				                                  : MEMACCESS_DebuggerMemory,
				                              FALSE);
			}
			msg_length = (u16)length;
		}

		if (error == DS_NoError)
			TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);

		if (error == DS_NoError)
			error = TRKAppendBuffer1_ui16(buffer, msg_length);

		if (error != DS_NoError) {
			switch (error) {
			case DS_CWDSException:
				replyError = DSREPLY_CWDSException;
				break;
			case DS_InvalidMemory:
				replyError = DSREPLY_InvalidMemoryRange;
				break;
			case DS_InvalidProcessID:
				replyError = DSREPLY_InvalidProcessID;
				break;
			case DS_InvalidThreadID:
				replyError = DSREPLY_InvalidThreadID;
				break;
			case DS_OSError:
				replyError = DSREPLY_OSError;
				break;
			default:
				replyError = DSREPLY_CWDSError;
				break;
			}
			error = TRKStandardACK(buffer, DSMSG_ReplyACK, replyError);
		} else {
			error = TRKSendACK(buffer);
		}
	}

	return error;
}

DSError TRKDoReadRegisters(TRKBuffer* buffer)
{
	DSError error;
	DSReplyError replyError;
	DSMessageRegisterOptions options;
	u32 registerDataLength;
	u16 msg_firstRegister;
	u16 msg_lastRegister;
	u8 msg_command;
	u8 msg_options;

	if (buffer->length != 6) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return;
	}
	TRKSetBufferPosition(buffer, DSREPLY_NoError);
	error = TRKReadBuffer1_ui8(buffer, &msg_command);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui8(buffer, &msg_options);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui16(buffer, &msg_firstRegister);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui16(buffer, &msg_lastRegister);

	if (msg_firstRegister > msg_lastRegister) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK,
		                       DSREPLY_InvalidRegisterRange);
		return;
	}

	if (error == DS_NoError)
		TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);

	options = (DSMessageRegisterOptions)(msg_options & 7);
	switch (options) {
	case DSREG_Default:
		error = TRKTargetAccessDefault(msg_firstRegister, msg_lastRegister,
		                               buffer, &registerDataLength, TRUE);
		break;
	case DSREG_FP:
		error = TRKTargetAccessFP(msg_firstRegister, msg_lastRegister, buffer,
		                          &registerDataLength, TRUE);
		break;
	case DSREG_Extended1:
		error = TRKTargetAccessExtended1(msg_firstRegister, msg_lastRegister,
		                                 buffer, &registerDataLength, TRUE);
		break;
	case DSREG_Extended2:
		error = TRKTargetAccessExtended2(msg_firstRegister, msg_lastRegister,
		                                 buffer, &registerDataLength, TRUE);
		break;
	default:
		error = DS_UnsupportedError;
		break;
	}

	if (error != DS_NoError) {
		switch (error) {
		case DS_UnsupportedError:
			replyError = DSREPLY_UnsupportedOptionError;
			break;
		case DS_InvalidRegister:
			replyError = DSREPLY_InvalidRegisterRange;
			break;
		case DS_CWDSException:
			replyError = DSREPLY_CWDSException;
			break;
		case DS_InvalidProcessID:
			replyError = DSREPLY_InvalidProcessID;
			break;
		case DS_InvalidThreadID:
			replyError = DSREPLY_InvalidThreadID;
			break;
		case DS_OSError:
			replyError = DSREPLY_OSError;
			break;
		default:
			replyError = DSREPLY_CWDSError;
		}

		error = TRKStandardACK(buffer, DSMSG_ReplyACK, replyError);
	} else {
		error = TRKSendACK(buffer);
	}
}

DSError TRKDoWriteRegisters(TRKBuffer* buffer)
{
	DSError error;
	DSReplyError replyError;
	DSMessageRegisterOptions options;
	u32 registerDataLength;
	u16 msg_firstRegister;
	u16 msg_lastRegister;
	u8 msg_command;
	u8 msg_options;

	if (buffer->length <= 6) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return;
	}
	TRKSetBufferPosition(buffer, DSREPLY_NoError);
	error = TRKReadBuffer1_ui8(buffer, &msg_command);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui8(buffer, &msg_options);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui16(buffer, &msg_firstRegister);

	if (error == DS_NoError)
		error = TRKReadBuffer1_ui16(buffer, &msg_lastRegister);

	if (msg_firstRegister > msg_lastRegister) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK,
		                       DSREPLY_InvalidRegisterRange);
		return;
	}

	options = (DSMessageRegisterOptions)msg_options;
	switch (options) {
	case DSREG_Default:
		error = TRKTargetAccessDefault(msg_firstRegister, msg_lastRegister,
		                               buffer, &registerDataLength, FALSE);
		break;
	case DSREG_FP:
		error = TRKTargetAccessFP(msg_firstRegister, msg_lastRegister, buffer,
		                          &registerDataLength, FALSE);
		break;
	case DSREG_Extended1:
		error = TRKTargetAccessExtended1(msg_firstRegister, msg_lastRegister,
		                                 buffer, &registerDataLength, FALSE);
		break;
	case DSREG_Extended2:
		error = TRKTargetAccessExtended2(msg_firstRegister, msg_lastRegister,
		                                 buffer, &registerDataLength, FALSE);
		break;
	default:
		error = DS_UnsupportedError;
		break;
	}

	if (error == DS_NoError)
		TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);

	if (error != DS_NoError) {
		switch (error) {
		case DS_UnsupportedError:
			replyError = DSREPLY_UnsupportedOptionError;
			break;
		case DS_InvalidRegister:
			replyError = DSREPLY_InvalidRegisterRange;
			break;
		case DS_MessageBufferReadError:
			replyError = DSREPLY_PacketSizeError;
			break;
		case DS_CWDSException:
			replyError = DSREPLY_CWDSException;
			break;
		case DS_InvalidProcessID:
			replyError = DSREPLY_InvalidProcessID;
			break;
		case DS_InvalidThreadID:
			replyError = DSREPLY_InvalidThreadID;
			break;
		case DS_OSError:
			replyError = DSREPLY_OSError;
			break;
		default:
			replyError = DSREPLY_CWDSError;
		}

		error = TRKStandardACK(buffer, DSMSG_ReplyACK, replyError);
	} else {
		error = TRKSendACK(buffer);
	}
}

DSError TRKDoFlushCache(TRKBuffer* buffer)
{
	DSError error;
	DSReplyError replyErr;
	u32 msg_start;
	u32 msg_end;
	u8 msg_command;
	u8 msg_options;

	if (buffer->length != 10) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return;
	}

	TRKSetBufferPosition(buffer, DSREPLY_NoError);
	error = TRKReadBuffer1_ui8(buffer, &msg_command);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui8(buffer, &msg_options);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui32(buffer, &msg_start);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui32(buffer, &msg_end);

	if (msg_start > msg_end) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK,
		                       DSREPLY_InvalidMemoryRange);
		return;
	}

	if (error == DS_NoError)
		error = TRKTargetFlushCache(msg_options, (void*)msg_start,
		                            (void*)msg_end);

	if (error == DS_NoError)
		TRKMessageIntoReply(buffer, DSMSG_ReplyACK, DSREPLY_NoError);

	if (error != DS_NoError) {
		switch (error) {
		case DS_UnsupportedError:
			replyErr = DSREPLY_UnsupportedOptionError;
			break;
		default:
			replyErr = DSREPLY_CWDSError;
			break;
		}

		error = TRKStandardACK(buffer, DSMSG_ReplyACK, replyErr);
	} else {
		error = TRKSendACK(buffer);
	}
}

DSError TRKDoContinue(TRKBuffer* buffer)
{
	DSError error;

	error = TRKTargetStopped();
	if (error == DS_NoError) {
		error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NotStopped);
		return;
	}

	error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
	if (error == DS_NoError)
		error = TRKTargetContinue();
}

DSError TRKDoStep(TRKBuffer* buffer)
{
	DSError error;
	u8 msg_command;
	u8 msg_options;
	u8 msg_count;
	u32 msg_rangeStart;
	u32 msg_rangeEnd;
	u32 pc;

	if (buffer->length < 3) {
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
		return;
	}

	TRKSetBufferPosition(buffer, DSREPLY_NoError);

	error = TRKReadBuffer1_ui8(buffer, &msg_command);
	if (error == DS_NoError)
		error = TRKReadBuffer1_ui8(buffer, &msg_options);

	switch (msg_options) {
	case DSSTEP_IntoCount:
	case DSSTEP_OverCount:
		if (error == DS_NoError)
			TRKReadBuffer1_ui8(buffer, &msg_count);
		if (msg_count >= 1) {
			break;
		}
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_ParameterError);
		return;
	case DSSTEP_IntoRange:
	case DSSTEP_OverRange:
		if (buffer->length != 10) {
			TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
			return;
		}

		if (error == DS_NoError)
			error = TRKReadBuffer1_ui32(buffer, &msg_rangeStart);
		if (error == DS_NoError)
			error = TRKReadBuffer1_ui32(buffer, &msg_rangeEnd);

		pc = TRKTargetGetPC();
		if (pc >= msg_rangeStart && pc <= msg_rangeEnd) {
			break;
		}
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_ParameterError);
		return;
	default:
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_UnsupportedOptionError);
		return;
	}

	if (!TRKTargetStopped()) {
		TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NotStopped);
		return;
	}

	error = TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_NoError);
	if (error == DS_NoError)
		switch (msg_options) {
		case DSSTEP_IntoCount:
		case DSSTEP_OverCount:
			error = TRKTargetSingleStep(msg_count,
										(msg_options == DSSTEP_OverCount));
			break;
		case DSSTEP_IntoRange:
		case DSSTEP_OverRange:
			error = TRKTargetStepOutOfRange(
				msg_rangeStart, msg_rangeEnd,
				(msg_options == DSSTEP_OverRange));
			break;
		}
}

DSError TRKDoStop(TRKBuffer* b)
{
	DSReplyError replyError;

	switch (TRKTargetStop()) {
	case DS_NoError:
		replyError = DSREPLY_NoError;
		break;
	case DS_InvalidProcessID:
		replyError = DSREPLY_InvalidProcessID;
		break;
	case DS_InvalidThreadID:
		replyError = DSREPLY_InvalidThreadID;
		break;
	case DS_OSError:
		replyError = DSREPLY_OSError;
		break;
	default:
		replyError = DSREPLY_Error;
		break;
	}

	return TRKStandardACK(b, DSMSG_ReplyACK, replyError);
}

DSError TRKDoSetOption(TRKBuffer* buffer) {
    DSError error;
    u8 spA;
    u8 sp9;
    u8 sp8;

    spA = 0;
    sp9 = 0;
    sp8 = 0;
    TRKSetBufferPosition(buffer, DSREPLY_NoError);
    error = TRKReadBuffer1_ui8(buffer, &spA);
    if (error == DS_NoError) {
        error = TRKReadBuffer1_ui8(buffer, &sp9);
    }
    if (error == DS_NoError) {
        error = TRKReadBuffer1_ui8(buffer, &sp8);
    }
    if (error != DS_NoError) {
        TRKResetBuffer(buffer, 1);
        if (buffer->position < 0x880) {
            buffer->data[buffer->position++] = 0x80;
            buffer->length++;
        }
        if (buffer->position < 0x880) {
            buffer->data[buffer->position++] = 1;
            buffer->length++;
        }
        TRKSendACK(buffer);
    } else if (sp9 == 1) {
        SetUseSerialIO(sp8);
    }
    TRKResetBuffer(buffer, 1);
    if (buffer->position < 0x880) {
        buffer->data[buffer->position++] = 0x80;
        buffer->length++;
    }
    if (buffer->position < 0x880) {
        buffer->data[buffer->position++] = 0;
        buffer->length++;
    }
    return TRKSendACK(buffer);
}
