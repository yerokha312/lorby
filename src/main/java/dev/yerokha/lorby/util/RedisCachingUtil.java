package dev.yerokha.lorby.util;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RedisCachingUtil {

    private static RedisTemplate<String, String> redisTemplate;

    public RedisCachingUtil(RedisTemplate<String, String> redisTemplate) {
        RedisCachingUtil.redisTemplate = redisTemplate;
    }

    public static void setValue(String key, String value, long timeout, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    public static Object getValue(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public static boolean containsKey(String key) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    public static void deleteKey(String key) {
        redisTemplate.delete(key);
    }
}
