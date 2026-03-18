'use strict';

const { getValidSession, invalidateSession } = require('./sessionManager');
const logger = require('./utils/logger');

const API_CALL_DELAY = Number(process.env.API_CALL_DELAY_MS) || 300;
const lastCallTime   = new Map();

// ─────────────────────────────────────────────────────────────────────────────
//  URL Parser — Apollo frontend URL → API payload
//
//  Supported URL params → API fields:
//
//  Person
//    personTitles[]                    → person_titles
//    personNotTitles[]                 → person_not_titles
//    personSeniorities[]               → person_seniorities
//    personLocations[]                 → person_locations
//    personNotLocations[]              → person_not_locations
//    personKeywords                    → q_person_keywords
//    personJobChangeType               → person_job_change_type
//    includeSimilarTitles              → include_similar_titles
//    prospectedByCurrentTeam[]         → prospected_by_current_team
//    phoneExists                       → phone_exists
//
//  Email
//    contactEmailStatusV2[]            → contact_email_status_v2
//    contactEmailExcludeCatchAll       → contact_email_exclude_catch_all
//
//  Organization
//    organizationIds[]                 → organization_ids           ← NEW
//    organizationNotIds[]              → organization_not_ids       ← NEW
//    organizationNumEmployeesRanges[]  → organization_num_employees_ranges
//    organizationLocations[]           → organization_locations
//    organizationNotLocations[]        → organization_not_locations
//    organizationIndustryTagIds[]      → organization_industry_tag_ids
//    organizationNotIndustryTagIds[]   → organization_not_industry_tag_ids
//    organizationKeywords              → q_organization_keyword_tags
//    qOrganizationKeywordTags[]        → q_organization_keyword_tags
//    organizationKeywordTags[]         → q_organization_keyword_tags (legacy)
//    qNotOrganizationKeywordTags[]     → q_not_organization_keyword_tags
//    includedOrganizationKeywordFields[] → included_organization_keyword_fields
//    excludedOrganizationKeywordFields[] → excluded_organization_keyword_fields
//    qOrganizationSearchListId         → q_organization_search_list_id
//    qNotOrganizationSearchListId      → q_not_organization_search_list_id
//
//  Revenue / Size
//    revenueRange[]                    → revenue_range
//    marketSegments[]                  → market_segments
//
//  Technology
//    currentlyUsingAnyOfTechnologyUids[] → currently_using_any_of_technology_uids
//
//  Search / View
//    qKeywords                         → q_keywords
//    sortByField                       → sort_by_field
//    sortAscending                     → sort_ascending
//    recommendationConfigId            → recommendation_config_id
//    finderViewId                      → finder_view_id
//    finderTableLayoutId               → finder_table_layout_id
//    uniqueUrlId                       → unique_url_id
// ─────────────────────────────────────────────────────────────────────────────

function parseApolloUrl(rawUrl) {
  let queryString = '';
  const hashIdx = rawUrl.indexOf('#');
  if (hashIdx !== -1) {
    const afterHash = rawUrl.slice(hashIdx + 1);
    const qIdx = afterHash.indexOf('?');
    if (qIdx !== -1) queryString = afterHash.slice(qIdx + 1);
  } else {
    const qIdx = rawUrl.indexOf('?');
    if (qIdx !== -1) queryString = rawUrl.slice(qIdx + 1);
  }

  if (!queryString) throw new Error('No query parameters found in URL');

  const params = new URLSearchParams(queryString);

  const payload = {
    sort_by_field:         params.get('sortByField') || '[none]',
    sort_ascending:        params.get('sortAscending') === 'true',
    page:                  1,
    display_mode:          'metadata_mode',
    per_page:              1,
    context:               'people-index-page',
    open_factor_names:     [],
    use_pending_signals:   false,
    use_cache:             false,
    num_fetch_result:      1,
    show_suggestions:      false,
    finder_verson:         2,
    search_session_id:     generateUuid(),
    ui_finder_random_seed: Math.random().toString(36).substring(2, 13),
    cacheKey:              Date.now(),
  };

  // ── Person ──────────────────────────────────────────────────────────────────

  const titles = params.getAll('personTitles[]');
  if (titles.length) payload.person_titles = titles;

  const notTitles = params.getAll('personNotTitles[]');
  if (notTitles.length) payload.person_not_titles = notTitles;

  const seniorities = params.getAll('personSeniorities[]');
  if (seniorities.length) payload.person_seniorities = seniorities;

  const departments = params.getAll('personDepartmentOrSubdepartments[]');
  if (departments.length) payload.person_department_or_subdepartments = departments;

  const personLocations = params.getAll('personLocations[]');
  if (personLocations.length) payload.person_locations = personLocations;

  const personNotLocations = params.getAll('personNotLocations[]');
  if (personNotLocations.length) payload.person_not_locations = personNotLocations;

  const personKeywords = params.get('personKeywords');
  if (personKeywords) payload.q_person_keywords = personKeywords;

  const jobChange = params.get('personJobChangeType');
  if (jobChange) payload.person_job_change_type = jobChange;

  const includeSimilarTitles = params.get('includeSimilarTitles');
  if (includeSimilarTitles !== null) payload.include_similar_titles = includeSimilarTitles === 'true';

  const prospectedByCurrentTeam = params.getAll('prospectedByCurrentTeam[]');
  if (prospectedByCurrentTeam.length) payload.prospected_by_current_team = prospectedByCurrentTeam;

  const phoneExists = params.get('phoneExists');
  if (phoneExists !== null) payload.phone_exists = phoneExists === 'true';

  // ── Email ───────────────────────────────────────────────────────────────────

  const emailStatuses = params.getAll('contactEmailStatusV2[]');
  if (emailStatuses.length) payload.contact_email_status_v2 = emailStatuses;

  const excludeCatchAll = params.get('contactEmailExcludeCatchAll');
  if (excludeCatchAll !== null) payload.contact_email_exclude_catch_all = excludeCatchAll === 'true';

  // ── Organization ─────────────────────────────────────────────────────────────

  // Specific company IDs (the "in these companies" filter in Apollo UI)
  const orgIds = params.getAll('organizationIds[]');
  if (orgIds.length) payload.organization_ids = orgIds;

  // Excluded company IDs
  const orgNotIds = params.getAll('organizationNotIds[]');
  if (orgNotIds.length) payload.organization_not_ids = orgNotIds;

  const orgSizes = params.getAll('organizationNumEmployeesRanges[]');
  if (orgSizes.length) payload.organization_num_employees_ranges = orgSizes;

  const orgLocations = params.getAll('organizationLocations[]');
  if (orgLocations.length) payload.organization_locations = orgLocations;

  const orgNotLocations = params.getAll('organizationNotLocations[]');
  if (orgNotLocations.length) payload.organization_not_locations = orgNotLocations;

  const orgIndustryTagIds = params.getAll('organizationIndustryTagIds[]');
  if (orgIndustryTagIds.length) payload.organization_industry_tag_ids = orgIndustryTagIds;

  const orgNotIndustryTagIds = params.getAll('organizationNotIndustryTagIds[]');
  if (orgNotIndustryTagIds.length) payload.organization_not_industry_tag_ids = orgNotIndustryTagIds;

  // Keyword tags (merge qOrganizationKeywordTags + legacy organizationKeywordTags)
  const qOrgKeywordTags      = params.getAll('qOrganizationKeywordTags[]');
  const legacyOrgKeywordTags = params.getAll('organizationKeywordTags[]');
  const allIncludedTags      = [...qOrgKeywordTags, ...legacyOrgKeywordTags];
  if (allIncludedTags.length) payload.q_organization_keyword_tags = allIncludedTags;

  const orgKeywords = params.get('organizationKeywords');
  if (orgKeywords) payload.q_organization_keyword_tags = orgKeywords;

  const qNotOrgKeywordTags = params.getAll('qNotOrganizationKeywordTags[]');
  if (qNotOrgKeywordTags.length) payload.q_not_organization_keyword_tags = qNotOrgKeywordTags;

  const includedOrgKeywordFields = params.getAll('includedOrganizationKeywordFields[]');
  if (includedOrgKeywordFields.length) payload.included_organization_keyword_fields = includedOrgKeywordFields;

  const excludedOrgKeywordFields = params.getAll('excludedOrganizationKeywordFields[]');
  if (excludedOrgKeywordFields.length) payload.excluded_organization_keyword_fields = excludedOrgKeywordFields;

  const listId = params.get('qOrganizationSearchListId');
  if (listId) payload.q_organization_search_list_id = listId;

  const notListId = params.get('qNotOrganizationSearchListId');
  if (notListId) payload.q_not_organization_search_list_id = notListId;

  // ── Revenue / Size ───────────────────────────────────────────────────────────

  const revenueRange = params.getAll('revenueRange[]');
  if (revenueRange.length) payload.revenue_range = revenueRange;

  const marketSegments = params.getAll('marketSegments[]');
  if (marketSegments.length) payload.market_segments = marketSegments;

  // ── Technology ───────────────────────────────────────────────────────────────

  const techUids = params.getAll('currentlyUsingAnyOfTechnologyUids[]');
  if (techUids.length) payload.currently_using_any_of_technology_uids = techUids;

  // ── Keywords / Search ────────────────────────────────────────────────────────

  const keywords = params.get('qKeywords');
  if (keywords) payload.q_keywords = keywords;

  // ── View / Sort ──────────────────────────────────────────────────────────────

  const recConfigId = params.get('recommendationConfigId');
  if (recConfigId) payload.recommendation_config_id = recConfigId;

  const finderViewId = params.get('finderViewId');
  if (finderViewId) payload.finder_view_id = finderViewId;

  const finderTableLayoutId = params.get('finderTableLayoutId');
  if (finderTableLayoutId) payload.finder_table_layout_id = finderTableLayoutId;

  const uniqueUrlId = params.get('uniqueUrlId');
  if (uniqueUrlId) payload.unique_url_id = uniqueUrlId;

  return payload;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Extract lead count
// ─────────────────────────────────────────────────────────────────────────────

function extractCount(data) {
  if (!data) return null;

  if (data.pipeline_total !== undefined) {
    const pt = data.pipeline_total;
    if (typeof pt === 'number') return pt;
    if (typeof pt === 'object' && pt !== null) {
      if (typeof pt.value === 'number') return pt.value;
      if (typeof pt.count === 'number') return pt.count;
      if (typeof pt.total === 'number') return pt.total;
    }
  }

  if (Array.isArray(data.breadcrumbs)) {
    for (const b of data.breadcrumbs) {
      if (b?.label?.toLowerCase?.()?.includes('total') || b?.type === 'total') {
        if (typeof b.value === 'number') return b.value;
        if (typeof b.count === 'number') return b.count;
      }
    }
    for (const b of data.breadcrumbs) {
      if (typeof b?.value === 'number') return b.value;
    }
  }

  if (typeof data.pagination?.total_entries === 'number') return data.pagination.total_entries;
  if (typeof data.total_people              === 'number') return data.total_people;
  if (typeof data.total_results             === 'number') return data.total_results;
  if (typeof data.total                     === 'number') return data.total;
  if (typeof data.count                     === 'number') return data.count;
  if (typeof data.metadata?.total_results   === 'number') return data.metadata.total_results;

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main export
// ─────────────────────────────────────────────────────────────────────────────

async function getLeadCount(apolloUrl) {
  const payload = parseApolloUrl(apolloUrl);
  logger.info('Apollo search payload built', {
    filters: Object.keys(payload).filter(k => ![
      'page','per_page','display_mode','context','cacheKey','search_session_id',
      'ui_finder_random_seed','finder_verson','open_factor_names',
      'use_pending_signals','use_cache','num_fetch_result','show_suggestions',
      'sort_by_field','sort_ascending',
    ].includes(k)),
  });

  const MAX_RETRIES = 3;
  let lastErr;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const session = await getValidSession();

    // Per-session rate-limit guard
    const last = lastCallTime.get(session.accountId) || 0;
    const gap  = Date.now() - last;
    if (gap < API_CALL_DELAY) await new Promise(r => setTimeout(r, API_CALL_DELAY - gap));

    try {
      const data = await _doApiCall(payload, session);
      lastCallTime.set(session.accountId, Date.now());

      const total = extractCount(data);
      if (total === null || total === undefined) {
        logger.warn('Could not parse lead count', { keys: Object.keys(data || {}) });
        throw new Error('Lead count not found in Apollo response');
      }

      logger.info('Lead count retrieved', { count: total, accountId: session.accountId });
      return Number(total);

    } catch (err) {
      lastErr = err;
      if (err.authError) {
        logger.warn('Auth error — invalidating session', { accountId: session.accountId });
        invalidateSession(session.accountId);
        await new Promise(r => setTimeout(r, 1000));
        continue;
      }
      if (err.status === 429) {
        logger.warn('Rate limited — backing off', { attempt });
        await new Promise(r => setTimeout(r, 5000 * attempt));
        continue;
      }
      throw err;
    }
  }

  throw lastErr ?? new Error('Max retries exceeded');
}

// ─────────────────────────────────────────────────────────────────────────────
//  API call via session's TLS client
// ─────────────────────────────────────────────────────────────────────────────

async function _doApiCall(payload, session) {
  const csrf    = session.headers?.['x-csrf-token'] || '';
  const tlsSess = session.tlsSession;

  const resp = await tlsSess.post(
    'https://app.apollo.io/api/v1/mixed_people/search_metadata_mode',
    {
      headers: {
        'content-type':      'application/json',
        'accept':            '*/*',
        'accept-language':   'en-US,en;q=0.9',
        'origin':            'https://app.apollo.io',
        'referer':           'https://app.apollo.io/',
        'user-agent':        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
        'x-csrf-token':      csrf,
        'x-referer-host':    'app.apollo.io',
        'x-referer-path':    '/people',
        'x-accept-language': 'en',
        'cookie':            session.cookieHeader,
      },
      body: JSON.stringify(payload),
    }
  );

  if (resp.status === 401 || resp.status === 403) {
    throw Object.assign(new Error(`Auth failed: HTTP ${resp.status}`), { authError: true });
  }
  if (resp.status === 429) {
    throw Object.assign(new Error('Rate limited'), { status: 429 });
  }
  if (resp.status !== 200) {
    throw new Error(`Apollo API HTTP ${resp.status}: ${String(resp.body).slice(0, 300)}`);
  }

  try {
    return JSON.parse(resp.body);
  } catch {
    throw new Error('Failed to parse Apollo response as JSON');
  }
}

function generateUuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

module.exports = { getLeadCount, parseApolloUrl };