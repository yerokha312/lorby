package dev.yerokha.lorby.repository;

import dev.yerokha.lorby.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Role findByAuthority(String authority);
}
