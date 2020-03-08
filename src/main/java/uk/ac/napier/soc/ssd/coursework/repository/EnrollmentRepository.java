package uk.ac.napier.soc.ssd.coursework.repository;

import uk.ac.napier.soc.ssd.coursework.domain.Enrollment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data  repository for the Enrollment entity.
 */
@SuppressWarnings("unused")
@Repository
public interface EnrollmentRepository extends JpaRepository<Enrollment, Long> {

    @Query("select enrollment from Enrollment enrollment where enrollment.user.login = ?#{principal.username}")
    List<Enrollment> findByUserIsCurrentUser();

    @Query(value = "select distinct enrollment from Enrollment enrollment left join fetch enrollment.courses",
        countQuery = "select count(distinct enrollment) from Enrollment enrollment")
    Page<Enrollment> findAllWithEagerRelationships(Pageable pageable);

    @Query(value = "select distinct enrollment from Enrollment enrollment left join fetch enrollment.courses")
    List<Enrollment> findAllWithEagerRelationships();

    @Query("select enrollment from Enrollment enrollment left join fetch enrollment.courses where enrollment.id =:id")
    Optional<Enrollment> findOneWithEagerRelationships(@Param("id") Long id);

}
