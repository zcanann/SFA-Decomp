// Function: FUN_801dd01c
// Entry: 801dd01c
// Size: 460 bytes

void FUN_801dd01c(uint param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  ushort *puVar5;
  double dVar6;
  int local_48;
  int local_44 [9];
  longlong local_20;
  
  puVar5 = *(ushort **)(param_1 + 0xb8);
  *(undefined *)((int)puVar5 + 3) = *(undefined *)(puVar5 + 1);
  uVar2 = FUN_80020078((uint)*puVar5);
  *(char *)(puVar5 + 1) = (char)uVar2;
  if (*(char *)((int)puVar5 + 3) != *(char *)(puVar5 + 1)) {
    if (*(char *)(puVar5 + 1) == '\0') {
      FUN_8000bb38(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e6274;
    }
    else {
      FUN_8000bb38(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e626c;
      bVar1 = false;
      uVar2 = FUN_80020078(0x81);
      if ((((uVar2 != 0) && (uVar2 = FUN_80020078(0x82), uVar2 != 0)) &&
          (uVar2 = FUN_80020078(0x83), uVar2 != 0)) && (uVar2 = FUN_80020078(0x84), uVar2 != 0)) {
        FUN_8000bb38(0,0x7e);
        bVar1 = true;
        iVar3 = FUN_8002e1f4(&local_48,local_44);
        puVar4 = (uint *)(iVar3 + local_48 * 4);
        for (; local_48 < local_44[0]; local_48 = local_48 + 1) {
          if ((*puVar4 != param_1) && (*(short *)(*puVar4 + 0x46) == 0x282)) {
            iVar3 = *(int *)(iVar3 + local_48 * 4);
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,6);
            break;
          }
          puVar4 = puVar4 + 1;
        }
        dVar6 = FUN_80014648();
        local_20 = (longlong)(int)(dVar6 / (double)FLOAT_803e6270);
        FUN_801dcec4();
      }
      if (!bVar1) {
        FUN_8000bb38(0,0x109);
      }
    }
  }
  FUN_8002fb40((double)*(float *)(puVar5 + 2),(double)FLOAT_803dc074);
  FUN_80037c38(param_1,8,0xff,0xff,0x78,0x129,(float *)&DAT_803de888);
  return;
}

