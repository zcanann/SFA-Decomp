// Function: FUN_802475e4
// Entry: 802475e4
// Size: 52 bytes

/* WARNING: Removing unreachable block (ram,0x80247610) */
/* WARNING: Removing unreachable block (ram,0x8024760c) */
/* WARNING: Removing unreachable block (ram,0x80247608) */
/* WARNING: Removing unreachable block (ram,0x80247604) */
/* WARNING: Removing unreachable block (ram,0x80247600) */
/* WARNING: Removing unreachable block (ram,0x802475fc) */
/* WARNING: Removing unreachable block (ram,0x802475f8) */
/* WARNING: Removing unreachable block (ram,0x802475f4) */
/* WARNING: Removing unreachable block (ram,0x802475f0) */
/* WARNING: Removing unreachable block (ram,0x802475ec) */
/* WARNING: Removing unreachable block (ram,0x802475e8) */
/* WARNING: Removing unreachable block (ram,0x802475e4) */

void FUN_802475e4(float *param_1,float *param_2)

{
  float fVar1;
  
  fVar1 = param_1[1];
  *param_2 = *param_1;
  param_2[1] = fVar1;
  fVar1 = param_1[3];
  param_2[2] = param_1[2];
  param_2[3] = fVar1;
  fVar1 = param_1[5];
  param_2[4] = param_1[4];
  param_2[5] = fVar1;
  fVar1 = param_1[7];
  param_2[6] = param_1[6];
  param_2[7] = fVar1;
  fVar1 = param_1[9];
  param_2[8] = param_1[8];
  param_2[9] = fVar1;
  fVar1 = param_1[0xb];
  param_2[10] = param_1[10];
  param_2[0xb] = fVar1;
  return;
}

