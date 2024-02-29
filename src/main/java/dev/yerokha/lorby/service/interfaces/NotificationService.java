package dev.yerokha.lorby.service.interfaces;

public interface NotificationService {

    void send(String to, String subject, String body);
}
