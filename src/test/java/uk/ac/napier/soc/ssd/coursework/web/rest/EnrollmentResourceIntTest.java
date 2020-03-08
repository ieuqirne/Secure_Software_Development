package uk.ac.napier.soc.ssd.coursework.web.rest;

import uk.ac.napier.soc.ssd.coursework.NapierUniPortalApp;

import uk.ac.napier.soc.ssd.coursework.domain.Enrollment;
import uk.ac.napier.soc.ssd.coursework.repository.EnrollmentRepository;
import uk.ac.napier.soc.ssd.coursework.repository.search.EnrollmentSearchRepository;
import uk.ac.napier.soc.ssd.coursework.web.rest.errors.ExceptionTranslator;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.web.PageableHandlerMethodArgumentResolver;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Base64Utils;

import javax.persistence.EntityManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


import static uk.ac.napier.soc.ssd.coursework.web.rest.TestUtil.createFormattingConversionService;
import static org.assertj.core.api.Assertions.assertThat;
import static org.elasticsearch.index.query.QueryBuilders.queryStringQuery;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import uk.ac.napier.soc.ssd.coursework.domain.enumeration.EntryLevel;
/**
 * Test class for the EnrollmentResource REST controller.
 *
 * @see EnrollmentResource
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = NapierUniPortalApp.class)
public class EnrollmentResourceIntTest {

    private static final EntryLevel DEFAULT_ENTRY_LEVEL = EntryLevel.BEGINNER;
    private static final EntryLevel UPDATED_ENTRY_LEVEL = EntryLevel.INTERMEDIATE;

    private static final String DEFAULT_COMMENTS = "AAAAAAAAAA";
    private static final String UPDATED_COMMENTS = "BBBBBBBBBB";

    @Autowired
    private EnrollmentRepository enrollmentRepository;
    @Mock
    private EnrollmentRepository enrollmentRepositoryMock;

    /**
     * This repository is mocked in the uk.ac.napier.soc.ssd.coursework.repository.search test package.
     *
     * @see uk.ac.napier.soc.ssd.coursework.repository.search.EnrollmentSearchRepositoryMockConfiguration
     */
    @Autowired
    private EnrollmentSearchRepository mockEnrollmentSearchRepository;

    @Autowired
    private MappingJackson2HttpMessageConverter jacksonMessageConverter;

    @Autowired
    private PageableHandlerMethodArgumentResolver pageableArgumentResolver;

    @Autowired
    private ExceptionTranslator exceptionTranslator;

    @Autowired
    private EntityManager em;

    private MockMvc restEnrollmentMockMvc;

    private Enrollment enrollment;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        final EnrollmentResource enrollmentResource = new EnrollmentResource(enrollmentRepository, mockEnrollmentSearchRepository);
        this.restEnrollmentMockMvc = MockMvcBuilders.standaloneSetup(enrollmentResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();
    }

    /**
     * Create an entity for this test.
     *
     * This is a static method, as tests for other entities might also need it,
     * if they test an entity which requires the current entity.
     */
    public static Enrollment createEntity(EntityManager em) {
        Enrollment enrollment = new Enrollment()
            .entryLevel(DEFAULT_ENTRY_LEVEL)
            .comments(DEFAULT_COMMENTS);
        return enrollment;
    }

    @Before
    public void initTest() {
        enrollment = createEntity(em);
    }

    @Test
    @Transactional
    public void createEnrollment() throws Exception {
        int databaseSizeBeforeCreate = enrollmentRepository.findAll().size();

        // Create the Enrollment
        restEnrollmentMockMvc.perform(post("/api/enrollments")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(enrollment)))
            .andExpect(status().isCreated());

        // Validate the Enrollment in the database
        List<Enrollment> enrollmentList = enrollmentRepository.findAll();
        assertThat(enrollmentList).hasSize(databaseSizeBeforeCreate + 1);
        Enrollment testEnrollment = enrollmentList.get(enrollmentList.size() - 1);
        assertThat(testEnrollment.getEntryLevel()).isEqualTo(DEFAULT_ENTRY_LEVEL);
        assertThat(testEnrollment.getComments()).isEqualTo(DEFAULT_COMMENTS);

        // Validate the Enrollment in Elasticsearch
        verify(mockEnrollmentSearchRepository, times(1)).save(testEnrollment);
    }

    @Test
    @Transactional
    public void createEnrollmentWithExistingId() throws Exception {
        int databaseSizeBeforeCreate = enrollmentRepository.findAll().size();

        // Create the Enrollment with an existing ID
        enrollment.setId(1L);

        // An entity with an existing ID cannot be created, so this API call must fail
        restEnrollmentMockMvc.perform(post("/api/enrollments")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(enrollment)))
            .andExpect(status().isBadRequest());

        // Validate the Enrollment in the database
        List<Enrollment> enrollmentList = enrollmentRepository.findAll();
        assertThat(enrollmentList).hasSize(databaseSizeBeforeCreate);

        // Validate the Enrollment in Elasticsearch
        verify(mockEnrollmentSearchRepository, times(0)).save(enrollment);
    }

    @Test
    @Transactional
    public void getAllEnrollments() throws Exception {
        // Initialize the database
        enrollmentRepository.saveAndFlush(enrollment);

        // Get all the enrollmentList
        restEnrollmentMockMvc.perform(get("/api/enrollments?sort=id,desc"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
            .andExpect(jsonPath("$.[*].id").value(hasItem(enrollment.getId().intValue())))
            .andExpect(jsonPath("$.[*].entryLevel").value(hasItem(DEFAULT_ENTRY_LEVEL.toString())))
            .andExpect(jsonPath("$.[*].comments").value(hasItem(DEFAULT_COMMENTS.toString())));
    }
    
    public void getAllEnrollmentsWithEagerRelationshipsIsEnabled() throws Exception {
        EnrollmentResource enrollmentResource = new EnrollmentResource(enrollmentRepositoryMock, mockEnrollmentSearchRepository);
        when(enrollmentRepositoryMock.findAllWithEagerRelationships(any())).thenReturn(new PageImpl(new ArrayList<>()));

        MockMvc restEnrollmentMockMvc = MockMvcBuilders.standaloneSetup(enrollmentResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();

        restEnrollmentMockMvc.perform(get("/api/enrollments?eagerload=true"))
        .andExpect(status().isOk());

        verify(enrollmentRepositoryMock, times(1)).findAllWithEagerRelationships(any());
    }

    public void getAllEnrollmentsWithEagerRelationshipsIsNotEnabled() throws Exception {
        EnrollmentResource enrollmentResource = new EnrollmentResource(enrollmentRepositoryMock, mockEnrollmentSearchRepository);
            when(enrollmentRepositoryMock.findAllWithEagerRelationships(any())).thenReturn(new PageImpl(new ArrayList<>()));
            MockMvc restEnrollmentMockMvc = MockMvcBuilders.standaloneSetup(enrollmentResource)
            .setCustomArgumentResolvers(pageableArgumentResolver)
            .setControllerAdvice(exceptionTranslator)
            .setConversionService(createFormattingConversionService())
            .setMessageConverters(jacksonMessageConverter).build();

        restEnrollmentMockMvc.perform(get("/api/enrollments?eagerload=true"))
        .andExpect(status().isOk());

            verify(enrollmentRepositoryMock, times(1)).findAllWithEagerRelationships(any());
    }

    @Test
    @Transactional
    public void getEnrollment() throws Exception {
        // Initialize the database
        enrollmentRepository.saveAndFlush(enrollment);

        // Get the enrollment
        restEnrollmentMockMvc.perform(get("/api/enrollments/{id}", enrollment.getId()))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
            .andExpect(jsonPath("$.id").value(enrollment.getId().intValue()))
            .andExpect(jsonPath("$.entryLevel").value(DEFAULT_ENTRY_LEVEL.toString()))
            .andExpect(jsonPath("$.comments").value(DEFAULT_COMMENTS.toString()));
    }
    @Test
    @Transactional
    public void getNonExistingEnrollment() throws Exception {
        // Get the enrollment
        restEnrollmentMockMvc.perform(get("/api/enrollments/{id}", Long.MAX_VALUE))
            .andExpect(status().isNotFound());
    }

    @Test
    @Transactional
    public void updateEnrollment() throws Exception {
        // Initialize the database
        enrollmentRepository.saveAndFlush(enrollment);

        int databaseSizeBeforeUpdate = enrollmentRepository.findAll().size();

        // Update the enrollment
        Enrollment updatedEnrollment = enrollmentRepository.findById(enrollment.getId()).get();
        // Disconnect from session so that the updates on updatedEnrollment are not directly saved in db
        em.detach(updatedEnrollment);
        updatedEnrollment
            .entryLevel(UPDATED_ENTRY_LEVEL)
            .comments(UPDATED_COMMENTS);

        restEnrollmentMockMvc.perform(put("/api/enrollments")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(updatedEnrollment)))
            .andExpect(status().isOk());

        // Validate the Enrollment in the database
        List<Enrollment> enrollmentList = enrollmentRepository.findAll();
        assertThat(enrollmentList).hasSize(databaseSizeBeforeUpdate);
        Enrollment testEnrollment = enrollmentList.get(enrollmentList.size() - 1);
        assertThat(testEnrollment.getEntryLevel()).isEqualTo(UPDATED_ENTRY_LEVEL);
        assertThat(testEnrollment.getComments()).isEqualTo(UPDATED_COMMENTS);

        // Validate the Enrollment in Elasticsearch
        verify(mockEnrollmentSearchRepository, times(1)).save(testEnrollment);
    }

    @Test
    @Transactional
    public void updateNonExistingEnrollment() throws Exception {
        int databaseSizeBeforeUpdate = enrollmentRepository.findAll().size();

        // Create the Enrollment

        // If the entity doesn't have an ID, it will be created instead of just being updated
        restEnrollmentMockMvc.perform(put("/api/enrollments")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(enrollment)))
            .andExpect(status().isBadRequest());

        // Validate the Enrollment in the database
        List<Enrollment> enrollmentList = enrollmentRepository.findAll();
        assertThat(enrollmentList).hasSize(databaseSizeBeforeUpdate);

        // Validate the Enrollment in Elasticsearch
        verify(mockEnrollmentSearchRepository, times(0)).save(enrollment);
    }

    @Test
    @Transactional
    public void deleteEnrollment() throws Exception {
        // Initialize the database
        enrollmentRepository.saveAndFlush(enrollment);

        int databaseSizeBeforeDelete = enrollmentRepository.findAll().size();

        // Get the enrollment
        restEnrollmentMockMvc.perform(delete("/api/enrollments/{id}", enrollment.getId())
            .accept(TestUtil.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        // Validate the database is empty
        List<Enrollment> enrollmentList = enrollmentRepository.findAll();
        assertThat(enrollmentList).hasSize(databaseSizeBeforeDelete - 1);

        // Validate the Enrollment in Elasticsearch
        verify(mockEnrollmentSearchRepository, times(1)).deleteById(enrollment.getId());
    }

    @Test
    @Transactional
    public void searchEnrollment() throws Exception {
        // Initialize the database
        enrollmentRepository.saveAndFlush(enrollment);
        when(mockEnrollmentSearchRepository.search(queryStringQuery("id:" + enrollment.getId())))
            .thenReturn(Collections.singletonList(enrollment));
        // Search the enrollment
        restEnrollmentMockMvc.perform(get("/api/_search/enrollments?query=id:" + enrollment.getId()))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
            .andExpect(jsonPath("$.[*].id").value(hasItem(enrollment.getId().intValue())))
            .andExpect(jsonPath("$.[*].entryLevel").value(hasItem(DEFAULT_ENTRY_LEVEL.toString())))
            .andExpect(jsonPath("$.[*].comments").value(hasItem(DEFAULT_COMMENTS.toString())));
    }

    @Test
    @Transactional
    public void equalsVerifier() throws Exception {
        TestUtil.equalsVerifier(Enrollment.class);
        Enrollment enrollment1 = new Enrollment();
        enrollment1.setId(1L);
        Enrollment enrollment2 = new Enrollment();
        enrollment2.setId(enrollment1.getId());
        assertThat(enrollment1).isEqualTo(enrollment2);
        enrollment2.setId(2L);
        assertThat(enrollment1).isNotEqualTo(enrollment2);
        enrollment1.setId(null);
        assertThat(enrollment1).isNotEqualTo(enrollment2);
    }
}
