package dev.yerokha.lorby.service;

public interface NotificationService {

    void send(String to, String subject, String body);
}
