#include <ntifs.h>
#include <intrin.h>

extern NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);
extern POBJECT_TYPE* IoDriverObjectType;

BOOLEAN Mdl_RWMemory(PVOID pBaseAddress, PVOID pData, ULONG DataSize, BOOLEAN isWrite)
{
	PMDL pMdl;
	PVOID pNewAddress;

	pMdl = IoAllocateMdl(pBaseAddress, DataSize, FALSE, FALSE, NULL);
	if (pMdl == NULL)
	{
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
	if (pNewAddress == NULL)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	__try {
		if (isWrite == TRUE)
		{
			RtlCopyMemory(pNewAddress, pData, DataSize);
		}
		else {
			RtlCopyMemory(pData, pNewAddress, DataSize);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		MmUnmapLockedPages(pNewAddress, pMdl);
		IoFreeMdl(pMdl);
		return FALSE;
	}
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObjct, PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING hookdllname;
	PDRIVER_OBJECT UseObject = NULL;
	PVOID mStart = 0;
	ULONG64 pTemp = 0;
	char rProcess[] = "x64dbg.exe\0";
	char hook1[] = { 0xEB };
	char hook2[] = { 0xE9,0x4C,0x01,0x00,0x00,0x90 };
	char hook3[] = { 0xE9,0xA6,0x00,0x00,0x00,0x90 };
	char hook4[] = { 0xE9,0x96,0x00,0x00,0x00,0x90 };
	char hook5[] = { 0xE9,0xA8,0x00,0x00,0x00,0x90 };
	char hook6[] = { 176,1 };
	char hook7[] = { 0x90,0x90 };
	RtlInitUnicodeString(&hookdllname, L"\\Driver\\mhyprot2");
	NTSTATUS status = ObReferenceObjectByName(&hookdllname, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, FILE_ALL_ACCESS, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&UseObject);
	if (NT_SUCCESS(status))
	{
		mStart = UseObject->DriverStart;

		//	hook csrss.exe的判断
		pTemp = (ULONG64)mStart + 0x77C0;
		Mdl_RWMemory((PVOID)pTemp, rProcess, 12, TRUE);
		//	hook 创建进程回调
		pTemp = (ULONG64)mStart + 0x3C19;
		Mdl_RWMemory((PVOID)pTemp, hook1, 1, TRUE);
		//	hook 加载模块回调
		pTemp = (ULONG64)mStart + 0x4158;
		Mdl_RWMemory((PVOID)pTemp, hook2, 6, TRUE);
		//	hook 创建线程回调
		pTemp = (ULONG64)mStart + 0x3D78;
		Mdl_RWMemory((PVOID)pTemp, hook3, 6, TRUE);
		//	hook 反内核调试
		pTemp = (ULONG64)mStart + 0x6789;
		Mdl_RWMemory((PVOID)pTemp, hook4, 6, TRUE);
		pTemp = (ULONG64)mStart + 0x13A8;
		Mdl_RWMemory((PVOID)pTemp, hook6, 2, TRUE);
		//	hook 反调试
		pTemp = (ULONG64)mStart + 0x5132;
		Mdl_RWMemory((PVOID)pTemp, hook5, 6, TRUE);
		pTemp = (ULONG64)mStart + 0x51DF;
		Mdl_RWMemory((PVOID)pTemp, hook6, 2, TRUE);
		//	hook 获取Peb数据
		pTemp = (ULONG64)mStart + 0x2783;
		Mdl_RWMemory((PVOID)pTemp, hook7, 2, TRUE);
		pTemp = (ULONG64)mStart + 0x2A31;
		Mdl_RWMemory((PVOID)pTemp, hook7, 2, TRUE);

		ObDereferenceObject(UseObject);
	}

	return STATUS_UNSUCCESSFUL;
}