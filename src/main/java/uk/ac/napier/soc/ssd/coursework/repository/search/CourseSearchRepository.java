package uk.ac.napier.soc.ssd.coursework.repository.search;

import uk.ac.napier.soc.ssd.coursework.domain.Course;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

/**
 * Spring Data Elasticsearch repository for the Course entity.
 */
public interface CourseSearchRepository extends ElasticsearchRepository<Course, Long> {
}
