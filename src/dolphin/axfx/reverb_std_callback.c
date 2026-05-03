#include <dolphin/axfx.h>

extern const f32 axfx_reverb_std_handle_f32_0p3;
extern const f32 axfx_reverb_std_handle_f32_0p6;
extern const double axfx_reverb_std_handle_i2f_magic;

asm static void HandleReverb2(register s32* sptr, register AXFX_REVSTD_WORK* rv) {
    nofralloc
	stwu r1, -144(r1)
	stmw r17, 8(r1)
	stfd f14, 88(r1)
	stfd f15, 96(r1)
	stfd f16, 104(r1)
	stfd f17, 112(r1)
	stfd f18, 120(r1)
	stfd f19, 128(r1)
	stfd f20, 136(r1)
	lis r31, axfx_reverb_std_handle_f32_0p3@ha
	lfs f6, axfx_reverb_std_handle_f32_0p3@l(r31)
	lis r31, axfx_reverb_std_handle_f32_0p6@ha
	lfs f9, axfx_reverb_std_handle_f32_0p6@l(r31)
	lis r31, axfx_reverb_std_handle_i2f_magic@ha
	lfd f5, axfx_reverb_std_handle_i2f_magic@l(r31)
	lfs f2, AXFX_REVSTD_WORK.allPassCoeff(rv)
	lfs f11, AXFX_REVSTD_WORK.damping(rv)
	lfs f8, AXFX_REVSTD_WORK.level(rv)
	fmuls f3, f8, f9
	fsubs f4, f9, f3
	lis r30, 0x4330
	stw r30, 80(r1)
	li r5, 0
L_00000638:
	slwi r31, r5, 3
	add r31, r31, rv
	lfs f19, AXFX_REVSTD_WORK.combCoef[0](r31)
	lfs f20, AXFX_REVSTD_WORK.combCoef[1](r31)
	slwi r31, r5, 2
	add r31, r31, rv
	lfs f7, AXFX_REVSTD_WORK.lpLastout[0](r31)
	lwz r27, AXFX_REVSTD_WORK.preDelayLine[0](r31)
	lwz r28, AXFX_REVSTD_WORK.preDelayPtr[0](r31)
	lwz r31, AXFX_REVSTD_WORK.preDelayTime(rv)
	subi r22, r31, 1
	slwi r22, r22, 2
	add r22, r22, r27
	cmpwi cr7, r31, 0
	mulli r31, r5, 0x28
	addi r29, rv, AXFX_REVSTD_WORK.C
	add r29, r29, r31
	addi r30, rv, AXFX_REVSTD_WORK.AP
	add r30, r30, r31
	lwz r21, AXFX_REVSTD_DELAYLINE.inPoint    + 0x00(r29)
	lwz r20, AXFX_REVSTD_DELAYLINE.outPoint   + 0x00(r29)
	lwz r19, AXFX_REVSTD_DELAYLINE.inPoint    + 0x14(r29)
	lwz r18, AXFX_REVSTD_DELAYLINE.outPoint   + 0x14(r29)
	lfs f15, AXFX_REVSTD_DELAYLINE.lastOutput + 0x00(r29)
	lfs f16, AXFX_REVSTD_DELAYLINE.lastOutput + 0x14(r29)
	lwz r26, AXFX_REVSTD_DELAYLINE.length     + 0x00(r29)
	lwz r25, AXFX_REVSTD_DELAYLINE.length     + 0x14(r29)
	lwz r7,  AXFX_REVSTD_DELAYLINE.inputs     + 0x00(r29)
	lwz r8,  AXFX_REVSTD_DELAYLINE.inputs     + 0x14(r29)
	lwz r12, AXFX_REVSTD_DELAYLINE.inPoint    + 0x00(r30)
	lwz r11, AXFX_REVSTD_DELAYLINE.outPoint   + 0x00(r30)
	lwz r10, AXFX_REVSTD_DELAYLINE.inPoint    + 0x14(r30)
	lwz r9,  AXFX_REVSTD_DELAYLINE.outPoint   + 0x14(r30)
	lfs f17, AXFX_REVSTD_DELAYLINE.lastOutput + 0x00(r30)
	lfs f18, AXFX_REVSTD_DELAYLINE.lastOutput + 0x14(r30)
	lwz r24, AXFX_REVSTD_DELAYLINE.length     + 0x00(r30)
	lwz r23, AXFX_REVSTD_DELAYLINE.length     + 0x14(r30)
	lwz r17, AXFX_REVSTD_DELAYLINE.inputs     + 0x00(r30)
	lwz r6,  AXFX_REVSTD_DELAYLINE.inputs     + 0x14(r30)
	lwz r30, 0(sptr)
	xoris r30, r30, 0x8000
	stw r30, 84(r1)
	lfd f12, 80(r1)
	fsubs f12, f12, f5
	li r31, 159
	mtctr r31
L_000006F0:
	fmr f13, f12
	beq cr7, L_00000710
	lfs f13, 0(r28)
	addi r28, r28, 4
	cmpw r28, r22
	stfs f12, -4(r28)
	bne+ L_00000710
	mr r28, r27
L_00000710:
	fmadds f8, f19, f15, f13
	lwzu r29, 4(sptr)
	fmadds f9, f20, f16, f13
	stfsx f8, r7, r21
	addi r21, r21, 4
	stfsx f9, r8, r19
	lfsx f14, r7, r20
	addi r20, r20, 4
	lfsx f16, r8, r18
	cmpw r21, r26
	cmpw cr1, r20, r26
	addi r19, r19, 4
	addi r18, r18, 4
	fmr f15, f14
	cmpw cr5, r19, r25
	fadds f14, f14, f16
	cmpw cr6, r18, r25
	bne+ L_0000075C
	li r21, 0
L_0000075C:
	xoris r29, r29, 0x8000
	fmadds f9, f2, f17, f14
	bne+ cr1, L_0000076C
	li r20, 0
L_0000076C:
	stw r29, 84(r1)
	bne+ cr5, L_00000778
	li r19, 0
L_00000778:
	stfsx f9, r17, r12
	fnmsubs f14, f2, f9, f17
	addi r12, r12, 4
	bne+ cr6, L_0000078C
	li r18, 0
L_0000078C:
	lfsx f17, r17, r11
	cmpw cr5, r12, r24
	addi r11, r11, 4
	cmpw cr6, r11, r24
	bne+ cr5, L_000007A4
	li r12, 0
L_000007A4:
	bne+ cr6, L_000007AC
	li r11, 0
L_000007AC:
	fmuls f14, f14, f6
	lfd f10, 80(r1)
	fmadds f14, f11, f7, f14
	fmadds f9, f2, f18, f14
	fmr f7, f14
	stfsx f9, r6, r10
	fnmsubs f14, f2, f9, f18
	fmuls f8, f4, f12
	lfsx f18, r6, r9
	addi r10, r10, 4
	addi r9, r9, 4
	fmadds f14, f3, f14, f8
	cmpw cr5, r10, r23
	cmpw cr6, r9, r23
	fctiwz f14, f14
	bne+ cr5, L_000007F0
	li r10, 0
L_000007F0:
	bne+ cr6, L_000007F8
	li r9, 0
L_000007F8:
	li r31, -4
	fsubs f12, f10, f5
	stfiwx f14, sptr, r31
	bdnz L_000006F0
	fmr f13, f12
	beq cr7, L_00000828
	lfs f13, 0(r28)
	addi r28, r28, 4
	cmpw r28, r22
	stfs f12, -4(r28)
	bne+ L_00000828
	mr r28, r27
L_00000828:
	fmadds f8, f19, f15, f13
	fmadds f9, f20, f16, f13
	stfsx f8, r7, r21
	addi r21, r21, 4
	stfsx f9, r8, r19
	lfsx f14, r7, r20
	addi r20, r20, 4
	lfsx f16, r8, r18
	cmpw r21, r26
	cmpw cr1, r20, r26
	addi r19, r19, 4
	addi r18, r18, 4
	fmr f15, f14
	cmpw cr5, r19, r25
	fadds f14, f14, f16
	cmpw cr6, r18, r25
	bne+ L_00000870
	li r21, 0
L_00000870:
	fmadds f9, f2, f17, f14
	bne+ cr1, L_0000087C
	li r20, 0
L_0000087C:
	bne+ cr5, L_00000884
	li r19, 0
L_00000884:
	stfsx f9, r17, r12
	fnmsubs f14, f2, f9, f17
	addi r12, r12, 4
	bne+ cr6, L_00000898
	li r18, 0
L_00000898:
	lfsx f17, r17, r11
	cmpw cr5, r12, r24
	addi r11, r11, 4
	cmpw cr6, r11, r24
	bne+ cr5, L_000008B0
	li r12, 0
L_000008B0:
	bne+ cr6, L_000008B8
	li r11, 0
L_000008B8:
	fmuls f14, f14, f6
	fmadds f14, f11, f7, f14
	mulli r31, r5, 0x28
	fmadds f9, f2, f18, f14
	fmr f7, f14
	addi r29, rv, AXFX_REVSTD_WORK.C
	add r29, r29, r31
	stfsx f9, r6, r10
	fnmsubs f14, f2, f9, f18
	fmuls f8, f4, f12
	lfsx f18, r6, r9
	addi r10, r10, 4
	addi r9, r9, 4
	fmadds f14, f3, f14, f8
	cmpw cr5, r10, r23
	cmpw cr6, r9, r23
	fctiwz f14, f14
	bne+ cr5, L_00000904
	li r10, 0
L_00000904:
	bne+ cr6, L_0000090C
	li r9, 0
L_0000090C:
	addi r30, rv, AXFX_REVSTD_WORK.AP
	add r30, r30, r31
	stfiwx f14, r0, sptr
	stw r21, AXFX_REVSTD_DELAYLINE.inPoint  + 0x00(r29)
	stw r20, AXFX_REVSTD_DELAYLINE.outPoint + 0x00(r29)
	stw r19, AXFX_REVSTD_DELAYLINE.inPoint  + 0x14(r29)
	stw r18, AXFX_REVSTD_DELAYLINE.outPoint + 0x14(r29)
	addi sptr, sptr, 4
	stfs f15, AXFX_REVSTD_DELAYLINE.lastOutput + 0x00(r29)
	stfs f16, AXFX_REVSTD_DELAYLINE.lastOutput + 0x14(r29)
	slwi r31, r5, 2
	add r31, r31, rv
	addi r5, r5, 1
	stw r12, AXFX_REVSTD_DELAYLINE.inPoint  + 0x00(r30)
	stw r11, AXFX_REVSTD_DELAYLINE.outPoint + 0x00(r30)
	stw r10, AXFX_REVSTD_DELAYLINE.inPoint  + 0x14(r30)
	stw r9, AXFX_REVSTD_DELAYLINE.outPoint  + 0x14(r30)
	cmpwi r5, 3
	stfs f17, AXFX_REVSTD_DELAYLINE.lastOutput + 0x00(r30)
	stfs f18, AXFX_REVSTD_DELAYLINE.lastOutput + 0x14(r30)
	stfs f7, AXFX_REVSTD_WORK.lpLastout(r31)
	stw r28, AXFX_REVSTD_WORK.preDelayPtr(r31)
	bne L_00000638
	lfd f14, 88(r1)
	lfd f15, 96(r1)
	lfd f16, 104(r1)
	lfd f17, 112(r1)
	lfd f18, 120(r1)
	lfd f19, 128(r1)
	lfd f20, 136(r1)
	lmw r17, 8(r1)
	addi r1, r1, 144
	blr
}

void ReverbSTDCallback(s32* left, s32* right, s32* surround, AXFX_REVSTD_WORK* rv) {
    HandleReverb2(left, rv);
}
