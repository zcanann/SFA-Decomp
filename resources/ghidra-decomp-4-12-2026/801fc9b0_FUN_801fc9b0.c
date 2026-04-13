// Function: FUN_801fc9b0
// Entry: 801fc9b0
// Size: 380 bytes

void FUN_801fc9b0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  undefined2 *puVar1;
  uint uVar2;
  short *psVar3;
  double dVar4;
  float afStack_28 [7];
  
  psVar3 = *(short **)(param_9 + 0xb8);
  puVar1 = FUN_8000facc();
  if ((-1 < *(char *)(psVar3 + 1)) && (uVar2 = FUN_80020078((int)*psVar3), uVar2 != 0)) {
    FUN_8000bb38(0,0x109);
    FUN_8000bb38(param_9,0x10d);
    FUN_8000bb38(param_9,0x494);
    *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0x7f | 0x80;
  }
  if (*(char *)(psVar3 + 1) < '\0') {
    dVar4 = (double)FLOAT_803dc074;
    FUN_8002fb40((double)FLOAT_803e6db0,dVar4);
    if ((*(byte *)(psVar3 + 1) >> 6 & 1) == 0) {
      if (FLOAT_803e6db4 <= *(float *)(param_9 + 0x98)) {
        FUN_80247eb8((float *)(puVar1 + 6),(float *)(param_9 + 0xc),afStack_28);
        FUN_80247ef8(afStack_28,afStack_28);
        FUN_80247edc((double)FLOAT_803e6db8,afStack_28,afStack_28);
        FUN_80247e94((float *)(param_9 + 0xc),afStack_28,(float *)(param_9 + 0xc));
        *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(param_9 + 0x1c) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(param_9 + 0x14);
        FUN_8009adfc((double)FLOAT_803e6dbc,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,1,0,0,0,0,0);
        *(byte *)(psVar3 + 1) = *(byte *)(psVar3 + 1) & 0xbf | 0x40;
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
      }
    }
  }
  return;
}

