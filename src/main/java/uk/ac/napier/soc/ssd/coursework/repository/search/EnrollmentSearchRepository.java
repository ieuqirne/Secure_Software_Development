package uk.ac.napier.soc.ssd.coursework.repository.search;

import uk.ac.napier.soc.ssd.coursework.domain.Enrollment;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

/**
 * Spring Data Elasticsearch repository for the Enrollment entity.
 */
public interface EnrollmentSearchRepository extends ElasticsearchRepository<Enrollment, Long> {
}
