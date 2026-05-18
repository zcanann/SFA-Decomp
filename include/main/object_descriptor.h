#ifndef MAIN_OBJECT_DESCRIPTOR_H_
#define MAIN_OBJECT_DESCRIPTOR_H_

#include "ghidra_import.h"

typedef void (*ObjectDescriptorCallback)(void);
typedef int (*ObjectDescriptorExtraSizeCallback)(void);

typedef struct ObjectDescriptor {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
} ObjectDescriptor;

typedef struct ObjectDescriptor11 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorCallback slot09;
  ObjectDescriptorCallback slot0A;
} ObjectDescriptor11;

typedef struct ObjectDescriptor12 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
} ObjectDescriptor12;

typedef struct ObjectDescriptor13 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
} ObjectDescriptor13;

typedef struct ObjectDescriptor14 {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorCallback slot09;
  ObjectDescriptorCallback slot0A;
  ObjectDescriptorCallback slot0B;
  ObjectDescriptorCallback slot0C;
  ObjectDescriptorCallback slot0D;
} ObjectDescriptor14;

#define OBJECT_DESCRIPTOR_FLAGS_10_SLOTS 0x00090000
#define OBJECT_DESCRIPTOR_FLAGS_11_SLOTS 0x000A0000
#define OBJECT_DESCRIPTOR_FLAGS_12_SLOTS 0x000B0000
#define OBJECT_DESCRIPTOR_FLAGS_13_SLOTS 0x000C0000
#define OBJECT_DESCRIPTOR_FLAGS_14_SLOTS 0x000D0000

#endif /* MAIN_OBJECT_DESCRIPTOR_H_ */
