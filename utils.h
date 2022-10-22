#pragma once

#include <winnt.h>

#define OBJ_CASE_INSENSITIVE    0x00000040L
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* NtOpenKey)(
	OUT PHANDLE KeyHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes
	);

typedef NTSTATUS (NTAPI* NtClose)(
	IN  HANDLE KeyHandle
);

typedef NTSTATUS (NTAPI* NtSetValueKey)(
	IN HANDLE			KeyHandle,
	IN PUNICODE_STRING	ValueName,
	IN ULONG			TitleIndex,			/* optional */
	IN ULONG			Type,
	IN PVOID			Data,
	IN ULONG			DataSize
	);

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

#define InitializeObjectAttributes(p, n, a, r, s) { \
     (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
     (p)->RootDirectory = r; \
     (p)->Attributes = a; \
     (p)->ObjectName = n; \
     (p)->SecurityDescriptor = s; \
     (p)->SecurityQualityOfService = NULL; \
     }