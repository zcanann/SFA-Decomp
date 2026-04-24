// Function: FUN_80128120
// Entry: 80128120
// Size: 848 bytes

void FUN_80128120(undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  ushort uVar2;
  undefined2 uVar3;
  byte *pbVar4;
  char cVar5;
  int iVar6;
  
  iVar6 = (int)(short)(200 - DAT_803dd75c);
  FUN_8011eda4((double)FLOAT_803e20d4,(double)FLOAT_803e20d8,DAT_803a89e8,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eb3c((double)FLOAT_803e1fa8,(double)FLOAT_803e20d8,DAT_803a89e8,iVar6,param_2,
               (int)FLOAT_803e1f34,0x1c,0x1e,1);
  FUN_8011eb3c((double)FLOAT_803e20d4,(double)FLOAT_803e20dc,DAT_803a89e8,iVar6,param_2,
               (int)FLOAT_803e1f34,0x1c,0x1e,2);
  FUN_8011eb3c((double)FLOAT_803e1fa8,(double)FLOAT_803e20dc,DAT_803a89e8,iVar6,param_2,
               (int)FLOAT_803e1f34,0x1c,0x1e,3);
  FUN_8011eb3c((double)FLOAT_803e20e0,(double)FLOAT_803e20e4,DAT_803a89ec,iVar6,param_2,
               (int)FLOAT_803e1f34,8,0x20,0);
  FUN_8011eb3c((double)FLOAT_803e20e0,(double)FLOAT_803e20e8,DAT_803a89ec,iVar6,param_2,
               (int)FLOAT_803e1f34,8,0x20,0);
  FUN_8011eda4((double)FLOAT_803e20ec,(double)FLOAT_803e1fd0,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eda4((double)FLOAT_803e20f0,(double)FLOAT_803e20f4,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eda4((double)FLOAT_803e20f8,(double)FLOAT_803e20f4,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eda4((double)FLOAT_803e20f0,(double)FLOAT_803e20fc,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eda4((double)FLOAT_803e20f8,(double)FLOAT_803e20fc,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  FUN_8011eda4((double)FLOAT_803e20ec,(double)FLOAT_803e2100,DAT_803a89f0,iVar6,param_2,
               (int)FLOAT_803e1f34,0);
  uVar2 = FUN_800ea2bc();
  if (uVar2 < 0xb4) {
    if (uVar2 < 0xb1) {
      if (uVar2 < 0x8b) {
        if (uVar2 < 0x72) {
          if (uVar2 < 0x49) {
            if (uVar2 < 9) {
              cVar1 = '\0';
            }
            else {
              cVar1 = '\x01';
            }
          }
          else {
            cVar1 = '\x02';
          }
        }
        else {
          cVar1 = '\x03';
        }
      }
      else {
        cVar1 = '\x04';
      }
    }
    else {
      cVar1 = '\x05';
    }
  }
  else {
    cVar1 = '\x06';
  }
  pbVar4 = &DAT_803dba9c;
  for (cVar5 = '\0'; cVar5 < '\x06'; cVar5 = cVar5 + '\x01') {
    uVar3 = 0x11;
    if (cVar1 <= cVar5) {
      uVar3 = 0xffff;
    }
    *(undefined2 *)(&DAT_8031bb90 + (uint)*pbVar4 * 0x20) = uVar3;
    pbVar4 = pbVar4 + 1;
  }
  return;
}

