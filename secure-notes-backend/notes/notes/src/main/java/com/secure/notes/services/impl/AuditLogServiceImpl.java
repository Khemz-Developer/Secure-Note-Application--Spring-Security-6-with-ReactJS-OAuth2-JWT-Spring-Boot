package com.secure.notes.services.impl;

import com.secure.notes.models.AuditLog;
import com.secure.notes.models.Note;
import com.secure.notes.repositories.AuditLogRepository;
import com.secure.notes.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogServiceImpl implements AuditLogService {

    @Autowired
    AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Note note){

        AuditLog auditLog = new AuditLog();
        auditLog.setAction("Note created");
        auditLog.setUsername(username);
        auditLog.setNoteId(note.getId());
        auditLog.setNoteContent(note.getContent());
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(auditLog);
    }

    @Override
    public void logNoteUpdate(String username, Note note){

            AuditLog auditLog = new AuditLog();
            auditLog.setAction("Note updated");
            auditLog.setUsername(username);
            auditLog.setNoteId(note.getId());
            auditLog.setNoteContent(note.getContent());
            auditLog.setTimestamp(LocalDateTime.now());
            auditLogRepository.save(auditLog);

    }

    @Override
    public void logNoteDeletion(String username, Long noteId){

        AuditLog auditLog = new AuditLog();
        auditLog.setAction("Note deleted");
        auditLog.setUsername(username);
        auditLog.setNoteId(noteId);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(auditLog);

    }

    @Override
    public List<AuditLog> getAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getNoteAuditLogs(Long noteId) {
        return auditLogRepository.findByNoteId(noteId);
    }
}
