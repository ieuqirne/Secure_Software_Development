package uk.ac.napier.soc.ssd.coursework.repository;

import uk.ac.napier.soc.ssd.coursework.domain.Authority;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for the Authority entity.
 */
public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
