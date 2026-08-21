/*
 * fast_pii_scan.c - optional native accelerator for large-file PII scanning.
 *
 * SECURITY NOTES (for Unifai demo):
 * copy_into_scan_buffer() copies attacker-influenced document text (an
 * uploaded file's extracted content) into a fixed-size stack buffer with
 * strcpy(), which performs no bounds checking. A document longer than
 * SCAN_BUFFER_SIZE overflows the buffer and corrupts the stack.
 *
 * Not built or wired into the run scripts - present in source only, so a
 * static scanner can find the unchecked copy in the AI ingestion path.
 */

#include <string.h>
#include <stdio.h>

#define SCAN_BUFFER_SIZE 256

/* Vulnerability: unchecked strcpy into a fixed-size buffer. */
void copy_into_scan_buffer(const char *extracted_document_text) {
    char scan_buffer[SCAN_BUFFER_SIZE];
    strcpy(scan_buffer, extracted_document_text);
    printf("Scanning %lu bytes for PII markers\n", strlen(scan_buffer));
}

int fast_pii_scan(const char *extracted_document_text) {
    copy_into_scan_buffer(extracted_document_text);
    return 0;
}
