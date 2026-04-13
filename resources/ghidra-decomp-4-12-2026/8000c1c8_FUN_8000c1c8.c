// Function: FUN_8000c1c8
// Entry: 8000c1c8
// Size: 600 bytes

void FUN_8000c1c8(undefined4 param_1,undefined4 param_2,char *param_3,float *param_4,float *param_5,
                 float *param_6,uint *param_7,uint *param_8,uint *param_9)

{
  byte bVar1;
  char cVar2;
  double dVar3;
  uint uVar4;
  short *psVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_8028682c();
  psVar5 = (short *)((ulonglong)uVar8 >> 0x20);
  if ((psVar5 != (short *)0x0) && (*(byte *)((int)psVar5 + 0x1f) >> 4 != 0)) {
    uVar6 = FUN_80022264(1,(uint)(ushort)psVar5[0xe]);
    if (*psVar5 == 0xab) {
      bVar1 = *(byte *)((int)psVar5 + 0x1f);
      if ((bVar1 & 0xf) == 0) {
        *(byte *)((int)psVar5 + 0x1f) = bVar1 & 0xf0 | 1;
      }
      else {
        *(byte *)((int)psVar5 + 0x1f) = bVar1 & 0xf0;
      }
      uVar7 = *(byte *)((int)psVar5 + 0x1f) & 0xf;
    }
    else {
      uVar7 = 0;
      for (; uVar4 = (uint)*(byte *)((int)psVar5 + uVar7 + 0x16), (int)uVar4 < (int)uVar6;
          uVar6 = uVar6 - uVar4) {
        uVar7 = uVar7 + 1;
      }
      if (((*(byte *)((int)psVar5 + 0x1f) & 0xf) == uVar7) &&
         (uVar7 = uVar7 + 1, (int)(uint)(*(byte *)((int)psVar5 + 0x1f) >> 4) <= (int)uVar7)) {
        uVar7 = 0;
      }
    }
    *(byte *)((int)psVar5 + 0x1f) = (byte)uVar7 & 0xf | *(byte *)((int)psVar5 + 0x1f) & 0xf0;
    *(short *)uVar8 = psVar5[uVar7 + 5];
    if (*(short *)uVar8 != 0) {
      uVar6 = (uint)*(byte *)((int)psVar5 + 3);
      if (uVar6 == 0) {
        *param_3 = *(char *)(psVar5 + 1);
      }
      else {
        uVar7 = FUN_80022264(0,uVar6);
        cVar2 = *(char *)(psVar5 + 1);
        uVar6 = FUN_80022264(0,uVar6);
        *param_3 = (cVar2 + (char)uVar7) - (char)uVar6;
      }
      uVar6 = (uint)*(byte *)((int)psVar5 + 5);
      if (uVar6 == 0) {
        *param_4 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(psVar5 + 2)) -
                          DOUBLE_803df208);
      }
      else {
        uVar7 = FUN_80022264(0,uVar6);
        bVar1 = *(byte *)(psVar5 + 2);
        uVar6 = FUN_80022264(0,uVar6);
        *param_4 = (float)((double)CONCAT44(0x43300000,(bVar1 + uVar7) - uVar6 ^ 0x80000000) -
                          DOUBLE_803df200);
      }
      dVar3 = DOUBLE_803df208;
      *param_5 = (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar5[3]) - DOUBLE_803df208);
      *param_6 = (float)((double)CONCAT44(0x43300000,(uint)(ushort)psVar5[4]) - dVar3);
      *param_7 = (uint)(byte)(&DAT_803dbea8)[*(byte *)(psVar5 + 0xf) >> 4];
      *param_8 = *(byte *)(psVar5 + 0xf) & 1;
      *param_9 = *(byte *)(psVar5 + 0xf) >> 3 & 1;
    }
  }
  FUN_80286878();
  return;
}

