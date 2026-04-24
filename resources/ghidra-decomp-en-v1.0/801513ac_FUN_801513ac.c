// Function: FUN_801513ac
// Entry: 801513ac
// Size: 688 bytes

void FUN_801513ac(short *param_1,int param_2)

{
  int iVar1;
  short sVar2;
  uint uVar3;
  undefined *puVar4;
  
  puVar4 = (&PTR_DAT_8031f178)[(uint)*(byte *)(param_2 + 0x33b) * 10];
  iVar1 = FUN_8014c11c((double)FLOAT_803e27ac,param_1,1,0x10,&DAT_803ac428);
  if (0 < iVar1) {
    if (((DAT_803ac42c < 0x29) && (*(short *)(param_2 + 0x2a0) != 3)) &&
       (*(short *)(param_2 + 0x2a0) != 4)) {
      sVar2 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(DAT_803ac428 + 0xc)),
                           (double)(*(float *)(param_1 + 10) - *(float *)(DAT_803ac428 + 0x14)));
      uVar3 = (uint)(short)(sVar2 - *param_1);
      if (0x8000 < (int)uVar3) {
        uVar3 = (uint)(short)((sVar2 - *param_1) + 1);
      }
      if ((short)uVar3 < -0x8000) {
        uVar3 = (uint)(short)((short)uVar3 + -1);
      }
      *(undefined *)(param_2 + 0x33a) =
           puVar4[8] + (&DAT_803dbc88)[(short)((uVar3 & 0xffff) >> 0xd)];
    }
    else if (DAT_803ac42c < 0x47) {
      while ((puVar4[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 10] & 1) != 0) {
        *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
        if ((byte)puVar4[8] < *(byte *)(param_2 + 0x33a)) {
          *(undefined *)(param_2 + 0x33a) = 1;
        }
      }
    }
  }
  if ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e2770) <
      FLOAT_803e27a8 * *(float *)(param_2 + 0x2ac)) {
    *(char *)(param_2 + 0x33a) = puVar4[8] + '\x01';
  }
  while( true ) {
    if ((*(uint *)(puVar4 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_2 + 0x2dc) &
        *(uint *)(puVar4 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if ((byte)puVar4[8] < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_2 + 0x2f2) = puVar4[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_2 + 0x2f3) = puVar4[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_2 + 0x2f4) = puVar4[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xc];
  iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0x10;
  FUN_8014d08c((double)*(float *)(puVar4 + iVar1),param_1,param_2,puVar4[iVar1 + 8],0,3);
  FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                 (uint)(byte)puVar4[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 8] * 4
                                 ),param_1);
  *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
  if ((byte)puVar4[8] < *(byte *)(param_2 + 0x33a)) {
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

