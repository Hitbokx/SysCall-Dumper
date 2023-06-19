#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <cassert>

int main( void )
{
	PIMAGE_DOS_HEADER pDosHeader{ (PIMAGE_DOS_HEADER)GetModuleHandle( L"ntdll.dll" ) };
	PIMAGE_NT_HEADERS pNtHeader{ (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew) };

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		assert( "Signature incorrect! \n" );


	PIMAGE_EXPORT_DIRECTORY pExportDirectory{ (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	if ( !pExportDirectory )
		assert( "pExportDirectory not found!\n" );

	PDWORD pEAT{ (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions) };
	PDWORD pENT{ (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames) };
	PWORD pEOT{ (PWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals) };

	unsigned char pBuf[32] = { 0 };
	const unsigned char pSig[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

	printf( "SYSCALL    ADDRESS      FUNCTION\n" );
	printf( "-----------------------------------------\n" );

	for ( size_t i{ 0 }; i < pExportDirectory->NumberOfFunctions; ++i )
	{
		memset( &pBuf, 0, 32 );

		PVOID pAddr{ (PVOID)((LPBYTE)pDosHeader + pEAT[pEOT[i]]) };
		char* szName{ (char*)pDosHeader + pENT[i] };

		// Exported by Ordinal
		if ( !szName || i >= pExportDirectory->NumberOfNames )
			std::cout << "Function of address " << std::hex << pAddr << " is exported by ordinal: " << std::dec << i << '\n';

		// Exported by Name
		else
		{
			if ( pAddr )
				memcpy( &pBuf, pAddr, 32 );

			if ( !pAddr || !szName )
				break;

			for ( size_t j = 0; j < sizeof( pSig ); ++j )
			{
				if ( pBuf[j] != pSig[j] )
					break;

				if ( j == sizeof( pSig ) - 1 )
				{
					printf( "0x%02X\t   %p\t%s\n", pBuf[4], pAddr, szName );
				}
			}
		}
	}

	std::getchar( );

	return 0;
}