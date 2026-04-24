// Function: FUN_80021494
// Entry: 80021494
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x80021614) */
/* WARNING: Removing unreachable block (ram,0x8002160c) */
/* WARNING: Removing unreachable block (ram,0x80021604) */
/* WARNING: Removing unreachable block (ram,0x800215fc) */
/* WARNING: Removing unreachable block (ram,0x800215f4) */
/* WARNING: Removing unreachable block (ram,0x800215ec) */
/* WARNING: Removing unreachable block (ram,0x800215e4) */
/* WARNING: Removing unreachable block (ram,0x800214d4) */
/* WARNING: Removing unreachable block (ram,0x800214cc) */
/* WARNING: Removing unreachable block (ram,0x800214c4) */
/* WARNING: Removing unreachable block (ram,0x800214bc) */
/* WARNING: Removing unreachable block (ram,0x800214b4) */
/* WARNING: Removing unreachable block (ram,0x800214ac) */
/* WARNING: Removing unreachable block (ram,0x800214a4) */

void FUN_80021494(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined2 *param_4,
                 undefined2 *param_5)

{
  int iVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar7;
  float local_b8 [4];
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  uVar7 = FUN_80286840();
  FUN_80247fb0((float *)uVar7,(float *)((ulonglong)uVar7 >> 0x20),local_b8);
  dVar3 = (double)FUN_802926a4();
  if ((double)FLOAT_803df448 <= dVar3) {
    dVar4 = (double)FUN_80292b24();
    dVar5 = (double)FLOAT_803df440;
    dVar4 = (double)(float)(dVar4 - dVar5);
  }
  else if (dVar3 <= (double)FLOAT_803df44c) {
    dVar4 = (double)FUN_80292b24();
    dVar5 = (double)FLOAT_803df440;
    dVar4 = (double)(float)(dVar5 - dVar4);
  }
  else {
    dVar4 = (double)FUN_80292b24();
    dVar5 = (double)FUN_80292b24();
  }
  fVar2 = FLOAT_803df454;
  dVar6 = (double)FLOAT_803df450;
  iVar1 = (int)((float)(dVar6 * dVar5) / FLOAT_803df454);
  local_a8 = (longlong)iVar1;
  *param_3 = (short)iVar1;
  iVar1 = (int)((float)(dVar6 * dVar3) / fVar2);
  local_a0 = (longlong)iVar1;
  *param_4 = (short)iVar1;
  iVar1 = (int)((float)(dVar6 * dVar4) / fVar2);
  local_98 = (longlong)iVar1;
  *param_5 = (short)iVar1;
  FUN_8028688c();
  return;
}

