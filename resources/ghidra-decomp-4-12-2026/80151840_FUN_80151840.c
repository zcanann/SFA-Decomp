// Function: FUN_80151840
// Entry: 80151840
// Size: 688 bytes

void FUN_80151840(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar4;
  double dVar5;
  
  puVar4 = (&PTR_DAT_8031fdc8)[(uint)*(byte *)(param_10 + 0x33b) * 10];
  iVar2 = FUN_8014c594(param_9,1,0x10,&DAT_803ad088);
  if (0 < iVar2) {
    if (((DAT_803ad08c < 0x29) && (*(short *)(param_10 + 0x2a0) != 3)) &&
       (*(short *)(param_10 + 0x2a0) != 4)) {
      iVar2 = FUN_80021884();
      sVar1 = (short)iVar2 - *param_9;
      uVar3 = (uint)sVar1;
      if (0x8000 < (int)uVar3) {
        uVar3 = (uint)(short)(sVar1 + 1);
      }
      if ((short)uVar3 < -0x8000) {
        uVar3 = (uint)(short)((short)uVar3 + -1);
      }
      *(undefined *)(param_10 + 0x33a) =
           puVar4[8] + (&DAT_803dc8f0)[(short)((uVar3 & 0xffff) >> 0xd)];
    }
    else if (DAT_803ad08c < 0x47) {
      while ((puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 10] & 1) != 0) {
        *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
        if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
          *(undefined *)(param_10 + 0x33a) = 1;
        }
      }
    }
  }
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x2a4)) -
                         DOUBLE_803e3408);
  if (dVar5 < (double)(FLOAT_803e3440 * *(float *)(param_10 + 0x2ac))) {
    *(char *)(param_10 + 0x33a) = puVar4[8] + '\x01';
  }
  while( true ) {
    if ((*(uint *)(puVar4 + (uint)*(byte *)(param_10 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_10 + 0x2dc) &
        *(uint *)(puVar4 + (uint)*(byte *)(param_10 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_10 + 0x2f2) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_10 + 0x2f3) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_10 + 0x2f4) = puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 0xc];
  iVar2 = (uint)*(byte *)(param_10 + 0x33a) * 0x10;
  FUN_8014d504((double)*(float *)(puVar4 + iVar2),dVar5,param_3,param_4,param_5,param_6,param_7,
               param_8,(int)param_9,param_10,(uint)(byte)puVar4[iVar2 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                 (uint)(byte)puVar4[(uint)*(byte *)(param_10 + 0x33a) * 0x10 + 8] *
                                 4),(int)param_9);
  *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
  if ((byte)puVar4[8] < *(byte *)(param_10 + 0x33a)) {
    *(undefined *)(param_10 + 0x33a) = 1;
  }
  return;
}

